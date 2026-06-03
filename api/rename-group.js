import { copyFile, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { promisify } from "node:util";

const pbkdf2 = promisify(crypto.pbkdf2);
const dataDir = process.env.DATA_DIR || "/data";
const authPath = path.join(dataDir, "auth.json");
const vaultPath = path.join(dataDir, "vault.json");
const authIterations = 210000;
const vaultIterations = 210000;
const roles = ["owner", "admin", "viewer"];

const knownPassword = process.env.KNOWN_PASSWORD || process.argv[2];
const rawFromGroup = process.env.FROM_GROUP ?? process.argv[3];
const rawToGroup = process.env.TO_GROUP ?? process.argv[4];
const fromGroup = normalizeGroup(rawFromGroup);
const toGroup = normalizeGroup(rawToGroup);

function base64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(value) {
  return Buffer.from(value, "base64");
}

function normalizeGroup(group) {
  const value = String(group || "").normalize("NFKC").trim().replace(/\s+/g, " ");
  return value || "默认分组";
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

async function findVaultKey(auth, password) {
  for (const role of roles) {
    const record = auth[role];
    if (!await verifyPasswordRecord(password, record)) continue;

    const wrappedKey = await unwrapRoleVaultKey(password, record).catch(() => null);
    if (wrappedKey) return wrappedKey;

    if ((role === "owner" || role === "admin") && auth.vaultSalt) {
      return deriveKey(password, fromBase64(auth.vaultSalt), auth.vaultIterations || vaultIterations);
    }
  }

  if (auth.authHash && auth.authSalt && await verifyPasswordRecord(password, {
    iterations: auth.authIterations || authIterations,
    salt: auth.authSalt,
    hash: auth.authHash,
  })) {
    return deriveKey(password, fromBase64(auth.vaultSalt), auth.vaultIterations || vaultIterations);
  }

  return null;
}

if (!knownPassword || !String(rawFromGroup || "").trim() || !String(rawToGroup || "").trim()) {
  console.error("Usage: node rename-group.js <known-password> <from-group> <to-group>");
  console.error("Environment variables are also supported: KNOWN_PASSWORD, FROM_GROUP, TO_GROUP.");
  process.exit(2);
}

if (toGroup.length > 40) {
  console.error("Target group name must be 40 characters or fewer.");
  process.exit(2);
}

const auth = JSON.parse(await readFile(authPath, "utf8"));
const vault = JSON.parse(await readFile(vaultPath, "utf8"));
const vaultKey = await findVaultKey(auth, knownPassword);

if (!vaultKey) {
  console.error("Known password could not unlock the vault. Nothing changed.");
  process.exit(1);
}

const entries = decryptEntries(vault, vaultKey);
let changed = 0;

const nextEntries = entries.map((entry) => {
  if (normalizeGroup(entry.group) !== fromGroup) return entry;
  changed += 1;
  return { ...entry, group: toGroup };
});

if (!changed) {
  console.log(`No entries found in group ${JSON.stringify(fromGroup)}. Nothing changed.`);
  process.exit(0);
}

const backupPath = `${vaultPath}.bak-${Date.now()}`;
await copyFile(vaultPath, backupPath);
await writeFile(vaultPath, `${JSON.stringify(encryptEntries(nextEntries, vaultKey), null, 2)}\n`, { encoding: "utf8", mode: 0o600 });

console.log(`Renamed ${changed} entr${changed === 1 ? "y" : "ies"} from ${JSON.stringify(fromGroup)} to ${JSON.stringify(toGroup)}.`);
console.log(`Vault backup: ${backupPath}`);
