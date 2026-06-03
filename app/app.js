const API_BASE = "/api";

const state = {
  entries: [],
  remaining: 30,
  lastRemaining: 30,
};

const $ = (id) => document.getElementById(id);
const shell = $("shell");
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

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });

  if (response.status === 204) return null;

  let payload = null;
  try {
    payload = await response.json();
  } catch (error) {
    payload = null;
  }

  if (!response.ok) {
    const message = payload?.error || "request_failed";
    throw new Error(message);
  }

  return payload;
}

function normalizeSecret(secret) {
  return secret.toUpperCase().replace(/\s|-/g, "").replace(/=+$/g, "");
}

function setHint(element, message, type = "") {
  element.textContent = message;
  element.className = `hint ${type}`.trim();
}

function showApp() {
  shell.classList.remove("is-locked");
  lockedView.hidden = true;
  appView.hidden = false;
  lockBtn.hidden = false;
  renderTokens();
}

function showLocked(message = "输入公司共享主密码后解锁云端保险库。首次使用会创建新的云端保险库。", type = "ok") {
  shell.classList.add("is-locked");
  appView.hidden = true;
  lockBtn.hidden = true;
  lockedView.hidden = false;
  $("passwordInput").value = "";
  tokenGrid.innerHTML = "";
  setHint(unlockHint, message, type);
}

function setTokenData(payload) {
  state.entries = payload.entries || [];
  state.remaining = payload.remaining || 30;
  state.lastRemaining = state.remaining;
}

function renderTokens() {
  tokenGrid.innerHTML = "";
  emptyState.hidden = state.entries.length > 0;
  countdown.textContent = `${state.remaining}s`;

  for (const item of state.entries) {
    const node = template.content.firstElementChild.cloneNode(true);
    node.querySelector(".issuer").textContent = item.issuer;
    node.querySelector(".account").textContent = item.account;

    const codeButton = node.querySelector(".code");
    codeButton.textContent = item.code;
    codeButton.addEventListener("click", async () => {
      await navigator.clipboard.writeText(item.code);
      const original = codeButton.textContent;
      codeButton.textContent = "已复制";
      setTimeout(() => { codeButton.textContent = original; }, 700);
    });

    node.querySelector(".delete").addEventListener("click", async () => {
      try {
        const payload = await api(`/entries/${encodeURIComponent(item.id)}`, { method: "DELETE" });
        setTokenData(payload);
        renderTokens();
      } catch (error) {
        alert("删除失败，请重新登录后再试。" );
      }
    });

    tokenGrid.appendChild(node);
  }

  updateProgress();
}

function updateProgress() {
  countdown.textContent = `${state.remaining}s`;
  document.querySelectorAll(".progress span").forEach((bar) => {
    bar.style.transform = `scaleX(${state.remaining / 30})`;
  });
}

async function refreshTokens() {
  const payload = await api("/tokens");
  setTokenData(payload);
  renderTokens();
}

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("passwordInput").value;
  setHint(unlockHint, "正在解锁云端保险库...");

  try {
    await api("/login", { method: "POST", body: JSON.stringify({ password }) });
    await refreshTokens();
    setHint(unlockHint, "已解锁", "ok");
    showApp();
  } catch (error) {
    const message = error.message === "password_too_short"
      ? "主密码至少需要 8 位。"
      : "主密码不正确，或云端保险库暂时无法访问。";
    setHint(unlockHint, message, "error");
  }
});

addForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const issuer = $("issuerInput").value.trim();
  const account = $("accountInput").value.trim();
  const secret = normalizeSecret($("secretInput").value);

  try {
    const payload = await api("/entries", {
      method: "POST",
      body: JSON.stringify({ issuer, account, secret }),
    });
    setTokenData(payload);
    addForm.reset();
    renderTokens();
  } catch (error) {
    alert("添加失败，请确认 Secret 是正确的 Base32 格式。" );
  }
});

lockBtn.addEventListener("click", async () => {
  try {
    await api("/logout", { method: "POST", body: "{}" });
  } catch (error) {
    // UI still locks even if the session already expired.
  }
  state.entries = [];
  state.remaining = 30;
  showLocked();
});

setInterval(async () => {
  if (appView.hidden) return;

  state.remaining = state.remaining <= 1 ? 30 : state.remaining - 1;
  updateProgress();

  if (state.remaining === 30 && state.lastRemaining !== 30) {
    try {
      await refreshTokens();
    } catch (error) {
      showLocked("登录已过期，请重新输入主密码。", "error");
    }
  }

  state.lastRemaining = state.remaining;
}, 1000);

showLocked();