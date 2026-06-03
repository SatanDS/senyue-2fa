const API_BASE = "/api";

const state = {
  entries: [],
  remaining: 30,
  lastRemaining: 30,
  role: "viewer",
  canManage: false,
  canManagePasswords: false,
  ownerConfigured: false,
  adminConfigured: false,
  viewerConfigured: false,
};

const roleLabels = {
  owner: "所有者",
  admin: "管理员",
  viewer: "员工查看",
};

const $ = (id) => document.getElementById(id);
const shell = $("shell");
const lockedView = $("lockedView");
const appView = $("appView");
const unlockForm = $("unlockForm");
const addForm = $("addForm");
const passwordForm = $("passwordForm");
const unlockHint = $("unlockHint");
const passwordHint = $("passwordHint");
const passwordStatus = $("passwordStatus");
const passwordRoleSelect = $("passwordRoleSelect");
const ownerConfirmLabel = $("ownerConfirmLabel");
const ownerConfirmInput = $("ownerConfirmInput");
const tokenGrid = $("tokenGrid");
const emptyState = $("emptyState");
const countdown = $("countdown");
const lockBtn = $("lockBtn");
const ownerPanel = $("ownerPanel");
const adminPanel = $("adminPanel");
const roleHint = $("roleHint");
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

function selectedRole() {
  return document.querySelector('input[name="loginRole"]:checked')?.value || "viewer";
}

function setSessionMeta(payload) {
  state.role = payload.role || state.role || "viewer";
  state.canManage = Boolean(payload.canManage);
  state.canManagePasswords = Boolean(payload.canManagePasswords);
  state.ownerConfigured = Boolean(payload.ownerConfigured);
  state.adminConfigured = Boolean(payload.adminConfigured);
  state.viewerConfigured = Boolean(payload.viewerConfigured);
}

function setTokenData(payload) {
  state.entries = payload.entries || [];
  state.remaining = payload.remaining || 30;
  state.lastRemaining = state.remaining;
  setSessionMeta(payload);
}

function updateRoleUi() {
  ownerPanel.hidden = !state.canManagePasswords;
  adminPanel.hidden = !state.canManage;

  if (state.role === "owner") {
    roleHint.textContent = "所有者模式：可修改所有用户组密码，也可添加、删除账号验证。";
  } else if (state.role === "admin") {
    roleHint.textContent = "管理员模式：可添加、删除账号验证，不能修改用户组密码。";
  } else {
    roleHint.textContent = "员工模式：只读查看，点击验证码可复制。";
  }

  passwordStatus.textContent = `当前状态：所有者${state.ownerConfigured ? "已设置" : "未设置"}，管理员${state.adminConfigured ? "已设置" : "未设置"}，员工${state.viewerConfigured ? "已设置" : "未设置"}。`;
}

function showApp() {
  shell.classList.remove("is-locked");
  lockedView.hidden = true;
  appView.hidden = false;
  lockBtn.hidden = false;
  updateRoleUi();
  renderTokens();
}

function showLocked(message = "员工、管理员、所有者分别使用各自密码登录。首次部署请选择所有者并创建密码。", type = "ok") {
  shell.classList.add("is-locked");
  appView.hidden = true;
  lockBtn.hidden = true;
  lockedView.hidden = false;
  ownerPanel.hidden = true;
  adminPanel.hidden = true;
  $("passwordInput").value = "";
  tokenGrid.innerHTML = "";
  setHint(unlockHint, message, type);
}

function markCopied(button) {
  const original = button.textContent;
  button.textContent = "已复制";
  button.classList.add("copied");
  setTimeout(() => {
    button.textContent = original;
    button.classList.remove("copied");
  }, 800);
}

function copyWithFallback(code) {
  const textarea = document.createElement("textarea");
  textarea.value = code;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.top = "-1000px";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();

  try {
    return document.execCommand("copy");
  } finally {
    document.body.removeChild(textarea);
  }
}

async function copyCode(code, button) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(code);
    } else if (!copyWithFallback(code)) {
      throw new Error("copy_failed");
    }
    markCopied(button);
  } catch (error) {
    if (copyWithFallback(code)) {
      markCopied(button);
      return;
    }
    window.prompt("复制失败，请手动复制验证码：", code);
  }
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
    codeButton.addEventListener("click", () => copyCode(item.code, codeButton));

    const deleteButton = node.querySelector(".delete");
    deleteButton.hidden = !state.canManage;
    deleteButton.addEventListener("click", async () => {
      if (!state.canManage) return;
      try {
        const payload = await api(`/entries/${encodeURIComponent(item.id)}`, { method: "DELETE" });
        setTokenData(payload);
        updateRoleUi();
        renderTokens();
      } catch (error) {
        alert(error.message === "manager_required" ? "只有所有者或管理员可以删除账号。" : "删除失败，请重新登录后再试。" );
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
  updateRoleUi();
  renderTokens();
}

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = $("passwordInput").value;
  const role = selectedRole();
  setHint(unlockHint, `正在进入${roleLabels[role]}模式...`);

  try {
    const login = await api("/login", { method: "POST", body: JSON.stringify({ password, role }) });
    setSessionMeta(login);
    await refreshTokens();
    setHint(unlockHint, "已解锁", "ok");
    showApp();
  } catch (error) {
    const message = error.message === "password_too_short"
      ? "密码至少需要 8 位。"
      : error.message === "owner_required"
        ? "首次创建保险库时请使用所有者身份登录。"
        : error.message === "invalid_password"
          ? "密码不正确，或角色选择不匹配。"
          : `云端保险库暂时无法访问：${error.message}`;
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
    updateRoleUi();
    addForm.reset();
    renderTokens();
  } catch (error) {
    const message = error.message === "manager_required"
      ? "只有所有者或管理员可以添加账号。"
      : "添加失败，请确认 Secret 是正确的 Base32 格式。";
    alert(message);
  }
});

passwordRoleSelect.addEventListener("change", () => {
  const isOwner = passwordRoleSelect.value === "owner";
  ownerConfirmLabel.hidden = !isOwner;
  if (!isOwner) ownerConfirmInput.checked = false;
});

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const role = passwordRoleSelect.value;
  const password = $("rolePasswordInput").value;
  if (!role) {
    setHint(passwordHint, "请先选择要修改的用户组。", "error");
    return;
  }
  if (role === "owner" && !ownerConfirmInput.checked) {
    setHint(passwordHint, "修改所有者密码前需要勾选确认。", "error");
    return;
  }
  setHint(passwordHint, `正在保存${roleLabels[role]}密码...`);

  try {
    const payload = await api(`/passwords/${role}`, {
      method: "PUT",
      body: JSON.stringify({ password, confirmOwnerChange: role === "owner" && ownerConfirmInput.checked }),
    });
    setSessionMeta(payload);
    updateRoleUi();
    passwordForm.reset();
    ownerConfirmLabel.hidden = true;
    ownerConfirmInput.checked = false;
    setHint(passwordHint, `${roleLabels[role]}密码已保存。`, "ok");
  } catch (error) {
    const message = error.message === "password_too_short"
      ? "密码至少需要 8 位。"
      : error.message === "owner_change_confirmation_required"
        ? "修改所有者密码前需要勾选确认。"
        : "保存失败，只有所有者可以修改用户组密码。";
    setHint(passwordHint, message, "error");
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
  state.role = "viewer";
  state.canManage = false;
  state.canManagePasswords = false;
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
      roleHint.textContent = `验证码刷新失败：${error.message}。请手动刷新页面或重新登录。`;
    }
  }

  state.lastRemaining = state.remaining;
}, 1000);

showLocked();