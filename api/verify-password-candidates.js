import { readFile } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { promisify } from "node:util";

const pbkdf2 = promisify(crypto.pbkdf2);
const dataDir = process.env.DATA_DIR || "/data";
const authPath = path.join(dataDir, "auth.json");
const vaultPath = path.join(dataDir, "vault.json");
const candidatesPath = process.argv[2] || process.env.CANDIDATES_FILE;
const authIterations = 210000;
const vaultIterations = 210000;
const roles = ["owner", "admin", "viewer"];

function fromBase64(value) {
  return Buffer.from(value, "base64");
}

async function hashPassword(password, salt, iterations = authIterations) {
  return pbkdf2(password, salt, iterations, 32, "sha256");
}

async function deriveKey(password, salt, iterations = vaultIterations) {
  return pbkdf2(password, salt, iterations, 32, "sha256");
}

async function deriveWrapKey(password, salt) {
  return pbkdf2(`vault-wrap:${password}`, salt, authIterations, 32, "sha256");
}

async function verifyPasswordRecord(password, record) {
  if (!record) return false;
  const expected = fromBase64(record.hash);
  const actual = await hashPassword(password, fromBase64(record.salt), record.iterations || authIterations);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function decryptVaultKey(payload, wrapKey) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", wrapKey, fromBase64(payload.iv));
  decipher.setAuthTag(fromBase64(payload.tag));
  return Buffer.concat([decipher.update(fromBase64(payload.data)), decipher.final()]);
}

async function unwrapRoleVaultKey(password, record) {
  if (!record?.wrapSalt || !record?.wrappedVaultKey) return null;
  const wrapKey = await deriveWrapKey(password, fromBase64(record.wrapSalt));
  return decryptVaultKey(record.wrappedVaultKey, wrapKey);
}

function decryptEntries(payload, key) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, fromBase64(payload.iv));
  decipher.setAuthTag(fromBase64(payload.tag));
  const decrypted = Buffer.concat([decipher.update(fromBase64(payload.data)), decipher.final()]);
  return JSON.parse(decrypted.toString("utf8"));
}

function legacyRecord(auth) {
  if (!auth?.authSalt || !auth?.authHash) return null;
  return {
    role: "legacy-owner",
    record: {
      iterations: auth.authIterations || authIterations,
      salt: auth.authSalt,
      hash: auth.authHash,
    },
  };
}

async function resolveVaultKey(auth, role, password, record) {
  const wrappedKey = await unwrapRoleVaultKey(password, record).catch(() => null);
  if (wrappedKey) return wrappedKey;

  if ((role === "owner" || role === "admin" || role === "legacy-owner") && auth.vaultSalt) {
    return deriveKey(password, fromBase64(auth.vaultSalt), auth.vaultIterations || vaultIterations);
  }

  return null;
}

function uniqueCandidates(lines) {
  const seen = new Set();
  const out = [];

  lines.forEach((line, index) => {
    const password = line.replace(/\r$/, "");
    if (!password || seen.has(password)) return;
    seen.add(password);
    out.push({ password, lineNumber: index + 1 });
  });

  return out;
}

if (!candidatesPath) {
  console.error("Usage: node verify-password-candidates.js /path/to/candidates.txt");
  console.error("Put one candidate password per line. Matching passwords are printed; secrets are never printed.");
  process.exit(2);
}

const auth = JSON.parse(await readFile(authPath, "utf8"));
const vault = JSON.parse(await readFile(vaultPath, "utf8"));
const lines = (await readFile(candidatesPath, "utf8")).split("\n");
const candidates = uniqueCandidates(lines);
const roleRecords = roles
  .filter((role) => auth[role])
  .map((role) => ({ role, record: auth[role] }));
const legacy = legacyRecord(auth);
if (legacy) roleRecords.push(legacy);

console.log(`Testing ${candidates.length} candidate password(s) against ${roleRecords.length} role record(s)...`);

for (const candidate of candidates) {
  for (const { role, record } of roleRecords) {
    const passwordOk = await verifyPasswordRecord(candidate.password, record);
    if (!passwordOk) continue;

    const vaultKey = await resolveVaultKey(auth, role, candidate.password, record);
    if (!vaultKey) {
      console.log(`HASH MATCH ONLY line=${candidate.lineNumber} role=${role} password=${JSON.stringify(candidate.password)} (vault key unavailable)`);
      continue;
    }

    try {
      const entries = decryptEntries(vault, vaultKey);
      console.log(`MATCH line=${candidate.lineNumber} role=${role} entries=${entries.length} password=${JSON.stringify(candidate.password)}`);
      process.exit(0);
    } catch (error) {
      console.log(`HASH MATCH ONLY line=${candidate.lineNumber} role=${role} password=${JSON.stringify(candidate.password)} (vault decrypt failed)`);
    }
  }
}

console.log("No candidate password unlocked the vault.");
process.exit(1);