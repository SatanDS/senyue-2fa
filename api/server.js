import http from "node:http";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { promisify } from "node:util";

const pbkdf2 = promisify(crypto.pbkdf2);
const port = Number(process.env.PORT || 3000);
const dataDir = process.env.DATA_DIR || "/data";
const authPath = path.join(dataDir, "auth.json");
const vaultPath = path.join(dataDir, "vault.json");
const sessionsPath = path.join(dataDir, "sessions.json");
const sessionSecretPath = path.join(dataDir, "session-secret");
const maxBodyBytes = 128 * 1024;
const sessions = new Map();
const authIterations = 210000;
const vaultIterations = 210000;
const sessionMaxAgeMs = 12 * 60 * 60 * 1000;
const sessionFileKey = await loadSessionFileKey();
const roles = new Set(["owner", "admin", "viewer"]);

function base64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(value) {
  return Buffer.from(value, "base64");
}

function sendJson(res, statusCode, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    ...headers,
  });
  res.end(body);
}

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || "").split(";").filter(Boolean).map((part) => {
    const [key, ...value] = part.trim().split("=");
    return [decodeURIComponent(key), decodeURIComponent(value.join("="))];
  }));
}

function sessionCookie(token) {
  return `senyue_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(sessionMaxAgeMs / 1000)}`;
}

function clearSessionCookie() {
  return "senyue_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";
}

async function loadSessionFileKey() {
  try {
    const raw = (await readFile(sessionSecretPath, "utf8")).trim();
    const key = fromBase64(raw);
    if (key.length === 32) return key;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  await mkdir(dataDir, { recursive: true });
  const key = crypto.randomBytes(32);
  await writeFile(sessionSecretPath, `${base64(key)}\n`, { encoding: "utf8", mode: 0o600 });
  return key;
}

async function readJson(filePath) {
  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function writeJsonAtomic(filePath, value) {
  await mkdir(dataDir, { recursive: true });
  const tempPath = `${filePath}.${process.pid}.tmp`;
  await writeFile(tempPath, JSON.stringify(value, null, 2), { encoding: "utf8", mode: 0o600 });
  await rename(tempPath, filePath);
}

function encryptSessionKey(key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", sessionFileKey, iv);
  const encrypted = Buffer.concat([cipher.update(key), cipher.final()]);
  return {
    iv: base64(iv),
    tag: base64(cipher.getAuthTag()),
    data: base64(encrypted),
  };
}

function decryptSessionKey(payload) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", sessionFileKey, fromBase64(payload.iv));
  decipher.setAuthTag(fromBase64(payload.tag));
  return Buffer.concat([decipher.update(fromBase64(payload.data)), decipher.final()]);
}

async function saveSessions() {
  const now = Date.now();
  const items = [];

  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt <= now) continue;
    items.push({
      token,
      role: session.role,
      expiresAt: session.expiresAt,
      ownerConfigured: Boolean(session.ownerConfigured),
      adminConfigured: Boolean(session.adminConfigured),
      viewerConfigured: Boolean(session.viewerConfigured),
      key: encryptSessionKey(session.key),
    });
  }

  await writeJsonAtomic(sessionsPath, { version: 1, sessions: items });
}

async function loadSessions() {
  const payload = await readJson(sessionsPath);
  if (!payload?.sessions) return;

  const now = Date.now();
  for (const item of payload.sessions) {
    if (!item.token || item.expiresAt <= now) continue;
    try {
      sessions.set(item.token, {
        role: item.role,
        expiresAt: item.expiresAt,
        ownerConfigured: Boolean(item.ownerConfigured),
        adminConfigured: Boolean(item.adminConfigured),
        viewerConfigured: Boolean(item.viewerConfigured),
        key: decryptSessionKey(item.key),
      });
    } catch (error) {
      console.error("Failed to restore session", error);
    }
  }
}
async function deriveKey(password, salt, iterations = vaultIterations) {
  return pbkdf2(password, salt, iterations, 32, "sha256");
}

async function hashPassword(password, salt, iterations = authIterations) {
  return pbkdf2(password, salt, iterations, 32, "sha256");
}

async function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16);
  const hash = await hashPassword(password, salt);
  return {
    iterations: authIterations,
    salt: base64(salt),
    hash: base64(hash),
  };
}

async function verifyPasswordRecord(password, record) {
  if (!record) return false;
  const expected = fromBase64(record.hash);
  const actual = await hashPassword(password, fromBase64(record.salt), record.iterations || authIterations);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

async function deriveWrapKey(password, salt) {
  return pbkdf2(`vault-wrap:${password}`, salt, authIterations, 32, "sha256");
}

function encryptVaultKey(vaultKey, wrapKey) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", wrapKey, iv);
  const encrypted = Buffer.concat([cipher.update(vaultKey), cipher.final()]);
  return {
    iv: base64(iv),
    tag: base64(cipher.getAuthTag()),
    data: base64(encrypted),
  };
}

function decryptVaultKey(payload, wrapKey) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", wrapKey, fromBase64(payload.iv));
  decipher.setAuthTag(fromBase64(payload.tag));
  return Buffer.concat([decipher.update(fromBase64(payload.data)), decipher.final()]);
}

async function createRoleRecord(password, vaultKey) {
  const record = await createPasswordRecord(password);
  const wrapSalt = crypto.randomBytes(16);
  const wrapKey = await deriveWrapKey(password, wrapSalt);
  return {
    ...record,
    wrapSalt: base64(wrapSalt),
    wrappedVaultKey: encryptVaultKey(vaultKey, wrapKey),
  };
}

async function unwrapRoleVaultKey(password, record) {
  if (!record?.wrapSalt || !record?.wrappedVaultKey) return null;
  const wrapKey = await deriveWrapKey(password, fromBase64(record.wrapSalt));
  return decryptVaultKey(record.wrappedVaultKey, wrapKey);
}

function legacyOwnerRecord(auth) {
  if (auth?.owner) return auth.owner;
  if (auth?.admin) return auth.admin;
  if (!auth?.authSalt || !auth?.authHash) return null;
  return {
    iterations: auth.authIterations || authIterations,
    salt: auth.authSalt,
    hash: auth.authHash,
  };
}

function authFlags(auth) {
  return {
    ownerConfigured: Boolean(auth?.owner),
    adminConfigured: Boolean(auth?.admin),
    viewerConfigured: Boolean(auth?.viewer),
  };
}

function sessionMeta(session) {
  return {
    role: session.role,
    canManage: session.role === "owner" || session.role === "admin",
    canManagePasswords: session.role === "owner",
    ownerConfigured: Boolean(session.ownerConfigured),
    adminConfigured: Boolean(session.adminConfigured),
    viewerConfigured: Boolean(session.viewerConfigured),
  };
}

async function createAuth(password) {
  const vaultKey = crypto.randomBytes(32);
  const owner = await createRoleRecord(password, vaultKey);
  const auth = {
    version: 3,
    authIterations,
    vaultIterations,
    vaultSalt: null,
    owner,
    admin: null,
    viewer: null,
  };

  await writeJsonAtomic(authPath, auth);
  await writeEncryptedVault([], vaultKey);

  return { key: vaultKey, role: "owner", ...authFlags(auth) };
}

async function ensureAuthVersion(auth) {
  if (!auth || auth.version >= 3) return auth;

  const migrated = {
    version: 3,
    authIterations: auth.authIterations || authIterations,
    vaultIterations: auth.vaultIterations || vaultIterations,
    vaultSalt: auth.vaultSalt || null,
    owner: legacyOwnerRecord(auth),
    admin: null,
    viewer: auth.viewer || null,
  };
  await writeJsonAtomic(authPath, migrated);
  return migrated;
}

async function resolveVaultKey(password, auth, record, role) {
  const wrappedKey = await unwrapRoleVaultKey(password, record);
  if (wrappedKey) return wrappedKey;

  if (role === "owner" && auth.vaultSalt) {
    return deriveKey(password, fromBase64(auth.vaultSalt), auth.vaultIterations || vaultIterations);
  }

  return null;
}

async function loginWithPassword(password, requestedRole) {
  let auth = await readJson(authPath);
  if (!auth) {
    if (requestedRole !== "owner") return { error: "owner_required" };
    return createAuth(password);
  }

  auth = await ensureAuthVersion(auth);
  const role = roles.has(requestedRole) ? requestedRole : "viewer";
  const record = auth[role];
  const passwordOk = await verifyPasswordRecord(password, record);

  if (!passwordOk) return null;

  const key = await resolveVaultKey(password, auth, record, role);
  if (!key) return null;

  return { key, role, ...authFlags(auth) };
}

function encryptEntries(entries, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(entries), "utf8"), cipher.final()]);
  return {
    version: 1,
    iv: base64(iv),
    tag: base64(cipher.getAuthTag()),
    data: base64(encrypted),
  };
}

function decryptEntries(payload, key) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, fromBase64(payload.iv));
  decipher.setAuthTag(fromBase64(payload.tag));
  const decrypted = Buffer.concat([decipher.update(fromBase64(payload.data)), decipher.final()]);
  return JSON.parse(decrypted.toString("utf8"));
}

async function readVault(key) {
  const payload = await readJson(vaultPath);
  if (!payload) return [];
  return decryptEntries(payload, key);
}

async function writeEncryptedVault(entries, key) {
  await writeJsonAtomic(vaultPath, encryptEntries(entries, key));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];

    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBodyBytes) {
        reject(new Error("request_body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

async function readRequestJson(req) {
  const body = await readBody(req);
  return body ? JSON.parse(body) : {};
}

function getSession(req) {
  const token = parseCookies(req).senyue_session;
  if (!token) return null;

  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }

  session.expiresAt = Date.now() + sessionMaxAgeMs;
  return { token, ...session };
}

function requireManager(session, res) {
  if (session.role === "owner" || session.role === "admin") return true;
  sendJson(res, 403, { error: "manager_required" });
  return false;
}

function requireOwner(session, res) {
  if (session.role === "owner") return true;
  sendJson(res, 403, { error: "owner_required" });
  return false;
}

function normalizeSecret(secret) {
  return String(secret || "").normalize("NFKC").toUpperCase().replace(/[\s\-\u200B-\u200D\uFEFF]/gu, "").replace(/=+$/g, "");
}

function decodeBase32(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = normalizeSecret(secret);
  let bits = "";
  const bytes = [];

  for (const char of normalized) {
    const value = alphabet.indexOf(char);
    if (value === -1) throw new Error("invalid_base32_secret");
    bits += value.toString(2).padStart(5, "0");
  }

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  if (!bytes.length) throw new Error("invalid_base32_secret");
  return Buffer.from(bytes);
}

function generateTotp(secret) {
  const counter = Math.floor(Date.now() / 1000 / 30);
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBytes.writeUInt32BE(counter >>> 0, 4);

  const hmac = crypto.createHmac("sha1", decodeBase32(secret)).update(counterBytes).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(binary % 1000000).padStart(6, "0");
}

function publicEntries(entries, session) {
  const seconds = Math.floor(Date.now() / 1000);
  return {
    ...sessionMeta(session),
    remaining: 30 - (seconds % 30),
    entries: entries.map((entry) => ({
      id: entry.id,
      issuer: entry.issuer,
      account: entry.account,
      code: generateTotp(entry.secret),
    })),
  };
}

function validateEntryPayload(payload) {
  const issuer = String(payload.issuer || "").trim();
  const account = String(payload.account || "").trim();
  const secret = normalizeSecret(payload.secret);

  if (!issuer || issuer.length > 80) throw new Error("invalid_issuer");
  if (!account || account.length > 120) throw new Error("invalid_account");
  decodeBase32(secret);

  return { issuer, account, secret };
}

async function refreshSessionFlags(session) {
  const auth = await ensureAuthVersion(await readJson(authPath));
  Object.assign(session, authFlags(auth));
  await saveSessions();
}

async function handleLogin(req, res) {
  const payload = await readRequestJson(req);
  const password = String(payload.password || "");
  const requestedRole = roles.has(payload.role) ? payload.role : "viewer";

  if (password.length < 8) {
    sendJson(res, 400, { error: "password_too_short" });
    return;
  }

  const login = await loginWithPassword(password, requestedRole);
  if (!login || login.error) {
    sendJson(res, login?.error === "owner_required" ? 409 : 401, { error: login?.error || "invalid_password" });
    return;
  }

  const token = base64(crypto.randomBytes(32));
  sessions.set(token, { ...login, expiresAt: Date.now() + sessionMaxAgeMs });
  await saveSessions();
  sendJson(res, 200, { ok: true, ...sessionMeta(login) }, { "Set-Cookie": sessionCookie(token) });
}

async function handleTokens(session, res) {
  await refreshSessionFlags(session);
  const entries = await readVault(session.key);
  sendJson(res, 200, publicEntries(entries, session));
}

async function handleCreateEntry(req, session, res) {
  if (!requireManager(session, res)) return;
  const payload = await readRequestJson(req);
  const entry = validateEntryPayload(payload);
  const entries = await readVault(session.key);
  entries.push({ id: crypto.randomUUID(), ...entry });
  await writeEncryptedVault(entries, session.key);
  sendJson(res, 201, publicEntries(entries, session));
}

async function handleDeleteEntry(id, session, res) {
  if (!requireManager(session, res)) return;
  const entries = await readVault(session.key);
  const nextEntries = entries.filter((entry) => entry.id !== id);
  await writeEncryptedVault(nextEntries, session.key);
  sendJson(res, 200, publicEntries(nextEntries, session));
}

async function handleSetRolePassword(role, req, session, res) {
  if (!requireOwner(session, res)) return;
  if (!roles.has(role)) {
    sendJson(res, 400, { error: "invalid_role" });
    return;
  }

  const payload = await readRequestJson(req);
  const password = String(payload.password || "");

  if (password.length < 8) {
    sendJson(res, 400, { error: "password_too_short" });
    return;
  }

  if (role === "owner" && payload.confirmOwnerChange !== true) {
    sendJson(res, 400, { error: "owner_change_confirmation_required" });
    return;
  }

  const auth = await ensureAuthVersion(await readJson(authPath));
  auth[role] = await createRoleRecord(password, session.key);
  await writeJsonAtomic(authPath, auth);

  Object.assign(session, authFlags(auth));
  await saveSessions();
  sendJson(res, 200, { ok: true, ...sessionMeta(session) });
}

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt < now) sessions.delete(token);
  }
}, 60 * 1000).unref();

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  try {
    if (req.method === "GET" && url.pathname === "/health") {
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === "POST" && url.pathname === "/login") {
      await handleLogin(req, res);
      return;
    }

    if (req.method === "POST" && url.pathname === "/logout") {
      const session = getSession(req);
      if (session) sessions.delete(session.token);
      await saveSessions();
      sendJson(res, 200, { ok: true }, { "Set-Cookie": clearSessionCookie() });
      return;
    }

    const session = getSession(req);
    if (!session) {
      sendJson(res, 401, { error: "unauthorized" });
      return;
    }

    if (req.method === "GET" && url.pathname === "/tokens") {
      await handleTokens(session, res);
      return;
    }

    if (req.method === "POST" && url.pathname === "/entries") {
      await handleCreateEntry(req, session, res);
      return;
    }

    const passwordMatch = url.pathname.match(/^\/passwords\/(owner|admin|viewer)$/);
    if (req.method === "PUT" && passwordMatch) {
      await handleSetRolePassword(passwordMatch[1], req, session, res);
      return;
    }

    if (req.method === "PUT" && url.pathname === "/viewer-password") {
      await handleSetRolePassword("viewer", req, session, res);
      return;
    }

    const deleteMatch = url.pathname.match(/^\/entries\/([^/]+)$/);
    if (req.method === "DELETE" && deleteMatch) {
      await handleDeleteEntry(decodeURIComponent(deleteMatch[1]), session, res);
      return;
    }

    sendJson(res, 404, { error: "not_found" });
  } catch (error) {
    const statusCode = error.message === "request_body_too_large" ? 413 : 500;
    const publicErrors = new Set(["invalid_base32_secret", "invalid_issuer", "invalid_account"]);
    if (!publicErrors.has(error.message) && error.message !== "request_body_too_large") {
      console.error("Request failed", error);
    }
    sendJson(res, publicErrors.has(error.message) ? 400 : statusCode, { error: error.message || "server_error" });
  }
});

await loadSessions();

server.listen(port, () => {
  console.log(`SenYue 2FA API listening on ${port}`);
});
