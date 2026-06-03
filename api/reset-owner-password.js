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
const newOwnerPassword = process.env.NEW_OWNER_PASSWORD || process.argv[3];

function base64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

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

function decryptVaultKey(payload, wrapKey) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", wrapKey, fromBase64(payload.iv));
  decipher.setAuthTag(fromBase64(payload.tag));
  return Buffer.concat([decipher.update(fromBase64(payload.data)), decipher.final()]);
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

async function unwrapRoleVaultKey(password, record) {
  if (!record?.wrapSalt || !record?.wrappedVaultKey) return null;
  const wrapKey = await deriveWrapKey(password, fromBase64(record.wrapSalt));
  return decryptVaultKey(record.wrappedVaultKey, wrapKey);
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

function decryptEntries(payload, key) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, fromBase64(payload.iv));
  decipher.setAuthTag(fromBase64(payload.tag));
  const decrypted = Buffer.concat([decipher.update(fromBase64(payload.data)), decipher.final()]);
  return JSON.parse(decrypted.toString("utf8"));
}

async function findVaultKey(auth, password) {
  for (const role of roles) {
    const record = auth[role];
    if (await verifyPasswordRecord(password, record)) {
      const wrappedKey = await unwrapRoleVaultKey(password, record);
      if (wrappedKey) return wrappedKey;

      if ((role === "owner" || role === "admin") && auth.vaultSalt) {
        return deriveKey(password, fromBase64(auth.vaultSalt), auth.vaultIterations || vaultIterations);
      }
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

if (!knownPassword || !newOwnerPassword) {
  console.error("Usage: node reset-owner-password.js <known-password> <new-owner-password>");
  console.error("Known password can be an existing owner/admin/viewer password that can open the vault.");
  process.exit(2);
}

if (newOwnerPassword.length < 8) {
  console.error("New owner password must be at least 8 characters.");
  process.exit(2);
}

const auth = JSON.parse(await readFile(authPath, "utf8"));
const vault = JSON.parse(await readFile(vaultPath, "utf8"));
const vaultKey = await findVaultKey(auth, knownPassword);

if (!vaultKey) {
  console.error("Known password could not unlock the vault key. Nothing changed.");
  process.exit(1);
}

try {
  decryptEntries(vault, vaultKey);
} catch (error) {
  console.error("Vault key check failed. Nothing changed.");
  process.exit(1);
}

const backupPath = `${authPath}.bak-${Date.now()}`;
await copyFile(authPath, backupPath);

auth.version = 3;
auth.authIterations = auth.authIterations || authIterations;
auth.vaultIterations = auth.vaultIterations || vaultIterations;
auth.owner = await createRoleRecord(newOwnerPassword, vaultKey);

delete auth.authSalt;
delete auth.authHash;

await writeFile(authPath, `${JSON.stringify(auth, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
console.log(`Owner password reset completed. Backup: ${backupPath}`);