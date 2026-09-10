/**
 * A minimal demo client for the auth API -- enough to exercise every
 * endpoint by hand, not a production frontend. The one pattern worth
 * copying into a real app is apiFetch()'s automatic refresh-and-retry
 * on a 401: it's what actually using a short-lived access token
 * looks like day to day, so a stub that skipped it would be
 * demonstrating something other than what this brick provides.
 */

const STORAGE_KEY = "auth-service-demo:tokens";

function loadTokens() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY));
  } catch {
    return null;
  }
}

function saveTokens(tokens) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(tokens));
}

function clearTokens() {
  localStorage.removeItem(STORAGE_KEY);
}

async function tryRefresh() {
  const tokens = loadTokens();
  if (!tokens?.refreshToken) return false;

  const res = await fetch("/api/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken: tokens.refreshToken }),
  });
  if (!res.ok) {
    clearTokens();
    return false;
  }
  const data = await res.json();
  saveTokens({ accessToken: data.accessToken, refreshToken: data.refreshToken });
  return true;
}

/** Fetches `/api${path}`, attaching the stored access token. On a 401
 * (expired access token -- they're short-lived on purpose) it tries
 * exactly one silent refresh-and-retry before giving up, so a still-
 * valid session doesn't interrupt the user just because 15 minutes
 * passed since their last request. */
async function apiFetch(path, options = {}, allowRefresh = true) {
  const tokens = loadTokens();
  const headers = { ...(options.headers || {}) };
  if (tokens?.accessToken) headers.Authorization = `Bearer ${tokens.accessToken}`;

  const res = await fetch(`/api${path}`, { ...options, headers });
  if (res.status === 401 && allowRefresh && tokens?.refreshToken) {
    if (await tryRefresh()) return apiFetch(path, options, false);
  }
  return res;
}

async function postJson(path, body) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// ---- flash messages ----

const flashEl = document.getElementById("flash");

function flash(message, kind = "info") {
  flashEl.textContent = message;
  flashEl.className = `flash ${kind}`;
  flashEl.hidden = false;
}

function clearFlash() {
  flashEl.hidden = true;
}

// ---- view routing ----

const views = document.querySelectorAll("[data-view]");
const navLinks = document.querySelectorAll("[data-nav]");
const logoutBtn = document.getElementById("logout-btn");

function isLoggedIn() {
  return Boolean(loadTokens()?.accessToken);
}

function updateNav() {
  document.querySelector('[data-nav="login"]').hidden = isLoggedIn();
  document.querySelector('[data-nav="register"]').hidden = isLoggedIn();
  document.querySelector('[data-nav="profile"]').hidden = !isLoggedIn();
  logoutBtn.hidden = !isLoggedIn();
}

function currentView() {
  const hash = window.location.hash.replace("#", "");
  return hash || "login";
}

async function render() {
  updateNav();
  clearFlash();
  const view = isLoggedIn() && (currentView() === "login" || currentView() === "register") ? "profile" : currentView();

  for (const section of views) {
    section.hidden = section.dataset.view !== view;
  }

  if (view === "reset-password") {
    const token = new URL(window.location.href).searchParams.get("token") || "";
    document.querySelector('#reset-password-form [name="token"]').value = token;
  }

  if (view === "verify-email") {
    await runEmailVerification();
  }

  if (view === "profile") {
    await loadProfile();
  }
}

async function runEmailVerification() {
  const statusEl = document.getElementById("verify-email-status");
  const token = new URL(window.location.href).searchParams.get("token");
  if (!token) {
    statusEl.textContent = "Lien de verification invalide (token manquant).";
    return;
  }

  const res = await postJson("/auth/verify-email", { token });
  const data = await res.json();
  statusEl.textContent = data.message ?? data.error;

  setTimeout(() => {
    window.location.hash = isLoggedIn() ? "#profile" : "#login";
  }, 1500);
}

window.addEventListener("hashchange", render);
logoutBtn.addEventListener("click", async () => {
  const tokens = loadTokens();
  if (tokens?.refreshToken) {
    await postJson("/auth/logout", { refreshToken: tokens.refreshToken }).catch(() => {});
  }
  clearTokens();
  window.location.hash = "#login";
  flash("Vous etes deconnecte.", "success");
});

// ---- forms ----

function formValues(form) {
  return Object.fromEntries(new FormData(form).entries());
}

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const { email, password } = formValues(event.target);
  const res = await postJson("/auth/login", { email, password });
  const data = await res.json();
  if (!res.ok) return flash(data.error, "error");
  saveTokens({ accessToken: data.accessToken, refreshToken: data.refreshToken });
  window.location.hash = "#profile";
});

document.getElementById("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const { email, password } = formValues(event.target);
  const res = await postJson("/auth/register", { email, password });
  const data = await res.json();
  if (!res.ok) return flash(data.error, "error");
  saveTokens({ accessToken: data.accessToken, refreshToken: data.refreshToken });
  window.location.hash = "#profile";
});

document.getElementById("forgot-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const { email } = formValues(event.target);
  const res = await postJson("/auth/forgot-password", { email });
  const data = await res.json();
  flash(data.message ?? data.error, res.ok ? "success" : "error");
});

document.getElementById("reset-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const { token, newPassword } = formValues(event.target);
  const res = await postJson("/auth/reset-password", { token, newPassword });
  const data = await res.json();
  if (!res.ok) return flash(data.error, "error");
  // The reset already revoked every refresh token server-side; clear
  // the locally-stored ones too so a still-live (short-lived) access
  // token from before the reset doesn't make render() think the user
  // is still logged in and skip straight past the login form.
  clearTokens();
  flash(data.message, "success");
  window.location.hash = "#login";
});

document.getElementById("resend-verification-btn").addEventListener("click", async () => {
  const tokens = loadTokens();
  if (!tokens) return;
  const meRes = await apiFetch("/me");
  const me = await meRes.json();
  const res = await postJson("/auth/resend-verification", { email: me.user.email });
  const data = await res.json();
  flash(data.message, "success");
});

// ---- profile ----

async function loadProfile() {
  const res = await apiFetch("/me");
  if (!res.ok) {
    clearTokens();
    window.location.hash = "#login";
    return;
  }
  const { user } = await res.json();
  document.getElementById("profile-email").textContent = user.email;
  document.getElementById("profile-verified").textContent = user.emailVerified ? "Oui" : "Non";
  document.getElementById("profile-created").textContent = new Date(user.createdAt).toLocaleString("fr-FR");
  document.getElementById("resend-verification-btn").hidden = user.emailVerified;
}

render();
