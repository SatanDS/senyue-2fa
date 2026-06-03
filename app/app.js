const STORAGE_KEY = "senyue-2fa-vault";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const state = {
  password: "",
  vault: [],
  lastCounter: Math.floor(Date.now() / 1000 / 30),
};

const $ = (id) => document.getElementById(id);
const lockedView = $("lockedView");
const appView = $("appView");
const unlockForm = $("unlockForm");
const addForm = $("addForm");
const unlockHint = $("unlockHint");
const tokenGrid = $("tokenGrid");
const emptyState = $("emptyState");
const countdown = $("countdown");
const lockBtn = $("lockBtn");
const template = $("tokenTemplate");

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function normalizeSecret(secret) {
  return secret.toUpperCase().replace(/\s|-/g, "").replace(/=+$/g, "");
}

function decodeBase32(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = normalizeSecret(secret);
  let bits = "";
  const bytes = [];

  for (const char of normalized) {
    const value = alphabet.indexOf(char);
    if (value === -1) throw new Error("Secret 必须是 Base32 格式");
    bits += value.toString(2).padStart(5, "0");
  }

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  if (!bytes.length) throw new Error("Secret 无效");
  return new Uint8Array(bytes);
}

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(password, vault) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(vault)));
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    version: 1,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(encrypted),
  }));
}

async function decryptVault(password) {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return [];

  const payload = JSON.parse(raw);
  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const data = base64ToBytes(payload.data);
  const key = await deriveKey(password, salt);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(decoder.decode(decrypted));
}

async function hotp(secretBytes, counter) {
  const counterBytes = new ArrayBuffer(8);
  const view = new DataView(counterBytes);
  view.setUint32(4, counter, false);

  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(binary % 1000000).padStart(6, "0");
}

async function generateTotp(secret) {
  const counterValue = Math.floor(Date.now() / 1000 / 30);
  return hotp(decodeBase32(secret), counterValue);
}

function setHint(element, message, type = "") {
  element.textContent = message;
  element.className = `hint ${type}`.trim();
}

async function saveVault() {
  await encryptVault(state.password, state.vault);
}

function showApp() {
  lockedView.hidden = true;
  appView.hidden = false;
  lockBtn.hidden = false;
  renderTokens();
}

function lock() {
  state.password = "";
  state.vault = [];
  appView.hidden = true;
  lockBtn.hidden = true;
  lockedView.hidden = false;
  $("passwordInput").value = "";
  setHint(unlockHint, "");
  tokenGrid.innerHTML = "";
}

async function renderTokens() {
  tokenGrid.innerHTML = "";
  emptyState.hidden = state.vault.length > 0;

  for (const item of state.vault) {
    const node = template.content.firstElementChild.cloneNode(true);
    node.querySelector(".issuer").textContent = item.issuer;
    node.querySelector(".account").textContent = item.account;
    const codeButton = node.querySelector(".code");
    codeButton.textContent = await generateTotp(item.secret);
    codeButton.addEventListener("click", async () => {
      await navigator.clipboard.writeText(codeButton.textContent);
      const original = codeButton.textContent;
      codeButton.textContent = "已复制";
      setTimeout(() => { codeButton.textContent = original; }, 700);
    });
    node.querySelector(".delete").addEventListener("click", async () => {
      state.vault = state.vault.filter((entry) => entry.id !== item.id);
      await saveVault();
      renderTokens();
    });
    tokenGrid.appendChild(node);
  }

  updateProgress();
}

function updateProgress() {
  const seconds = Math.floor(Date.now() / 1000);
  const remaining = 30 - (seconds % 30);
  countdown.textContent = `${remaining}s`;
  document.querySelectorAll(".progress span").forEach((bar) => {
    bar.style.transform = `scaleX(${remaining / 30})`;
  });
}

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("passwordInput").value;
  setHint(unlockHint, "正在解锁...");

  try {
    state.vault = await decryptVault(password);
    state.password = password;
    setHint(unlockHint, "已解锁", "ok");
    showApp();
  } catch (error) {
    setHint(unlockHint, "主密码不正确，或本地保险库已损坏。", "error");
  }
});

addForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const issuer = $("issuerInput").value.trim();
  const account = $("accountInput").value.trim();
  const secret = normalizeSecret($("secretInput").value);

  try {
    await generateTotp(secret);
    state.vault.push({ id: crypto.randomUUID(), issuer, account, secret });
    await saveVault();
    addForm.reset();
    renderTokens();
  } catch (error) {
    alert(error.message || "Secret 无效");
  }
});

lockBtn.addEventListener("click", lock);

setInterval(() => {
  updateProgress();
  const currentCounter = Math.floor(Date.now() / 1000 / 30);
  if (!appView.hidden && currentCounter !== state.lastCounter) {
    state.lastCounter = currentCounter;
    renderTokens();
  }
}, 1000);

if (!localStorage.getItem(STORAGE_KEY)) {
  setHint(unlockHint, "首次输入的主密码会用于创建本地加密保险库。至少 8 位。", "ok");
}



