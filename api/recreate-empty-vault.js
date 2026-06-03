import { copyFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { promisify } from "node:util";

const pbkdf2 = promisify(crypto.pbkdf2);
const dataDir = process.env.DATA_DIR || "/data";
const authPath = path.join(dataDir, "auth.json");
const vaultPath = path.join(dataDir, "vault.json");
const authIterations = 210000;
const newOwnerPassword = process.env.NEW_OWNER_PASSWORD || process.argv[2];

function base64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

async function hashPassword(password, salt) {
  return pbkdf2(password, salt, authIterations, 32, "sha256");
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

async function createRoleRecord(password, vaultKey) {
  const salt = crypto.randomBytes(16);
  const hash = await hashPassword(password, salt);
  const wrapSalt = crypto.randomBytes(16);
  const wrapKey = await deriveWrapKey(password, wrapSalt);

  return {
    iterations: authIterations,
    salt: base64(salt),
    hash: base64(hash),
    wrapSalt: base64(wrapSalt),
    wrappedVaultKey: encryptVaultKey(vaultKey, wrapKey),
  };
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

async function backupIfExists(filePath, stamp) {
  try {
    const backupPath = `${filePath}.bak-${stamp}`;
    await copyFile(filePath, backupPath);
    return backupPath;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

if (!newOwnerPassword) {
  console.error("Usage: node recreate-empty-vault.js <new-owner-password>");
  process.exit(2);
}

if (newOwnerPassword.length < 8) {
  console.error("New owner password must be at least 8 characters.");
  process.exit(2);
}

await mkdir(dataDir, { recursive: true });
const stamp = Date.now();
const authBackup = await backupIfExists(authPath, stamp);
const vaultBackup = await backupIfExists(vaultPath, stamp);
const vaultKey = crypto.randomBytes(32);

const auth = {
  version: 3,
  authIterations,
  vaultIterations: 210000,
  vaultSalt: null,
  owner: await createRoleRecord(newOwnerPassword, vaultKey),
  admin: null,
  viewer: null,
};

await writeFile(authPath, `${JSON.stringify(auth, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
await writeFile(vaultPath, `${JSON.stringify(encryptEntries([], vaultKey), null, 2)}\n`, { encoding: "utf8", mode: 0o600 });

console.log("New empty vault created.");
if (authBackup) console.log(`Auth backup: ${authBackup}`);
if (vaultBackup) console.log(`Vault backup: ${vaultBackup}`);