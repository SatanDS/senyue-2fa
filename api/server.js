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
const maxBodyBytes = 128 * 1024;
const sessions = new Map();
const authIterations = 210000;
const vaultIterations = 210000;
const sessionMaxAgeMs = 12 * 60 * 60 * 1000;

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

async function deriveKey(password, salt, iterations = vaultIterations) {
  return pbkdf2(password, salt, iterations, 32, "sha256");
}

async function hashPassword(password, salt) {
  return pbkdf2(password, salt, authIterations, 32, "sha256");
}

async function createAuth(password) {
  const authSalt = crypto.randomBytes(16);
  const vaultSalt = crypto.randomBytes(16);
  const authHash = await hashPassword(password, authSalt);
  const vaultKey = await deriveKey(password, vaultSalt);

  await writeJsonAtomic(authPath, {
    version: 1,
    authIterations,
    vaultIterations,
    authSalt: base64(authSalt),
    authHash: base64(authHash),
    vaultSalt: base64(vaultSalt),
  });
  await writeEncryptedVault([], vaultKey);

  return vaultKey;
}

async function verifyPassword(password) {
  const auth = await readJson(authPath);
  if (!auth) return createAuth(password);

  const authSalt = fromBase64(auth.authSalt);
  const expected = fromBase64(auth.authHash);
  const actual = await hashPassword(password, authSalt);

  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    return null;
  }

  return deriveKey(password, fromBase64(auth.vaultSalt), auth.vaultIterations || vaultIterations);
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

function normalizeSecret(secret) {
  return String(secret || "").toUpperCase().replace(/\s|-/g, "").replace(/=+$/g, "");
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

function publicEntries(entries) {
  const seconds = Math.floor(Date.now() / 1000);
  return {
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

async function handleLogin(req, res) {
  const payload = await readRequestJson(req);
  const password = String(payload.password || "");

  if (password.length < 8) {
    sendJson(res, 400, { error: "password_too_short" });
    return;
  }

  const key = await verifyPassword(password);
  if (!key) {
    sendJson(res, 401, { error: "invalid_password" });
    return;
  }

  const token = base64(crypto.randomBytes(32));
  sessions.set(token, { key, expiresAt: Date.now() + sessionMaxAgeMs });
  sendJson(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(token) });
}

async function handleTokens(session, res) {
  const entries = await readVault(session.key);
  sendJson(res, 200, publicEntries(entries));
}

async function handleCreateEntry(req, session, res) {
  const payload = await readRequestJson(req);
  const entry = validateEntryPayload(payload);
  const entries = await readVault(session.key);
  entries.push({ id: crypto.randomUUID(), ...entry });
  await writeEncryptedVault(entries, session.key);
  sendJson(res, 201, publicEntries(entries));
}

async function handleDeleteEntry(id, session, res) {
  const entries = await readVault(session.key);
  const nextEntries = entries.filter((entry) => entry.id !== id);
  await writeEncryptedVault(nextEntries, session.key);
  sendJson(res, 200, publicEntries(nextEntries));
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

    const deleteMatch = url.pathname.match(/^\/entries\/([^/]+)$/);
    if (req.method === "DELETE" && deleteMatch) {
      await handleDeleteEntry(decodeURIComponent(deleteMatch[1]), session, res);
      return;
    }

    sendJson(res, 404, { error: "not_found" });
  } catch (error) {
    const statusCode = error.message === "request_body_too_large" ? 413 : 500;
    const publicErrors = new Set(["invalid_base32_secret", "invalid_issuer", "invalid_account"]);
    sendJson(res, publicErrors.has(error.message) ? 400 : statusCode, { error: error.message || "server_error" });
  }
});

server.listen(port, () => {
  console.log(`SenYue 2FA API listening on ${port}`);
});