import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { createServer } from "../server.js";

let server;
let baseUrl;

before(async () => {
  server = createServer({ dbPath: ":memory:", jwtSecret: "test-secret-do-not-use-in-prod" });
  await new Promise((resolve) => server.listen(0, resolve));
  baseUrl = `http://localhost:${server.address().port}`;
});

after(() => {
  server.close();
});

async function request(method, path, body, headers) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

let userCounter = 0;
function freshCredentials() {
  userCounter += 1;
  return { email: `user${userCounter}@example.com`, password: "correct-horse-1" };
}

async function registerAndLogin() {
  const creds = freshCredentials();
  const res = await request("POST", "/api/auth/register", creds);
  return { creds, ...res.body };
}

// ---- register ----

test("POST /api/auth/register", async (t) => {
  await t.test("creates a user and returns tokens, never the password hash", async () => {
    const creds = freshCredentials();
    const res = await request("POST", "/api/auth/register", creds);
    assert.equal(res.status, 201);
    assert.equal(res.body.user.email, creds.email);
    assert.equal(res.body.user.emailVerified, false);
    assert.equal(res.body.user.passwordHash, undefined);
    assert.ok(res.body.accessToken);
    assert.ok(res.body.refreshToken);
  });

  await t.test("rejects an invalid email", async () => {
    const res = await request("POST", "/api/auth/register", { email: "not-an-email", password: "correct-horse-1" });
    assert.equal(res.status, 400);
  });

  await t.test("rejects a weak password", async () => {
    const res = await request("POST", "/api/auth/register", { email: "weak@example.com", password: "short" });
    assert.equal(res.status, 400);
  });

  await t.test("rejects a duplicate email", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);
    const res = await request("POST", "/api/auth/register", creds);
    assert.equal(res.status, 409);
  });

  await t.test("email matching is case-insensitive for duplicates", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);
    const res = await request("POST", "/api/auth/register", { ...creds, email: creds.email.toUpperCase() });
    assert.equal(res.status, 409);
  });
});

// ---- login ----

test("POST /api/auth/login", async (t) => {
  await t.test("succeeds with the correct password", async () => {
    const { creds } = await registerAndLogin();
    const res = await request("POST", "/api/auth/login", creds);
    assert.equal(res.status, 200);
    assert.equal(res.body.user.email, creds.email);
    assert.ok(res.body.accessToken);
  });

  await t.test("rejects the wrong password with a generic message", async () => {
    const { creds } = await registerAndLogin();
    const res = await request("POST", "/api/auth/login", { ...creds, password: "wrong-password-1" });
    assert.equal(res.status, 401);
    assert.equal(res.body.error, "Invalid email or password.");
  });

  await t.test("rejects an unknown email with the same generic message", async () => {
    const res = await request("POST", "/api/auth/login", { email: "nobody@example.com", password: "whatever-1" });
    assert.equal(res.status, 401);
    assert.equal(res.body.error, "Invalid email or password.");
  });

  await t.test("login is case-insensitive on email", async () => {
    const { creds } = await registerAndLogin();
    const res = await request("POST", "/api/auth/login", { ...creds, email: creds.email.toUpperCase() });
    assert.equal(res.status, 200);
  });
});

// ---- me ----

test("GET /api/me", async (t) => {
  await t.test("returns the authenticated user with a valid bearer token", async () => {
    const { accessToken, user } = await registerAndLogin();
    const res = await request("GET", "/api/me", undefined, { Authorization: `Bearer ${accessToken}` });
    assert.equal(res.status, 200);
    assert.equal(res.body.user.id, user.id);
  });

  await t.test("401 with no Authorization header", async () => {
    const res = await request("GET", "/api/me");
    assert.equal(res.status, 401);
  });

  await t.test("401 with a garbage token", async () => {
    const res = await request("GET", "/api/me", undefined, { Authorization: "Bearer not-a-real-jwt" });
    assert.equal(res.status, 401);
  });

  await t.test("401 with an expired access token", async () => {
    const shortLivedServer = createServer({
      dbPath: ":memory:",
      jwtSecret: "another-secret",
      accessTokenTtlSeconds: -1,
    });
    await new Promise((resolve) => shortLivedServer.listen(0, resolve));
    const shortBaseUrl = `http://localhost:${shortLivedServer.address().port}`;
    try {
      const registerRes = await fetch(`${shortBaseUrl}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(freshCredentials()),
      });
      const { accessToken } = await registerRes.json();
      const meRes = await fetch(`${shortBaseUrl}/api/me`, { headers: { Authorization: `Bearer ${accessToken}` } });
      assert.equal(meRes.status, 401);
    } finally {
      shortLivedServer.close();
    }
  });
});

// ---- refresh ----

test("POST /api/auth/refresh", async (t) => {
  await t.test("rotates the refresh token and issues a new access token", async () => {
    const { refreshToken } = await registerAndLogin();
    const res = await request("POST", "/api/auth/refresh", { refreshToken });
    assert.equal(res.status, 200);
    assert.ok(res.body.accessToken);
    assert.notEqual(res.body.refreshToken, refreshToken);
  });

  await t.test("the old refresh token no longer works after rotation", async () => {
    const { refreshToken } = await registerAndLogin();
    await request("POST", "/api/auth/refresh", { refreshToken });
    const res = await request("POST", "/api/auth/refresh", { refreshToken });
    assert.equal(res.status, 401);
  });

  await t.test("reusing a rotated-out token revokes the whole session, including the token issued by rotation", async () => {
    const { refreshToken } = await registerAndLogin();
    const rotated = await request("POST", "/api/auth/refresh", { refreshToken });

    // Replay the old (now-revoked) token -- this should nuke every
    // refresh token for the user, not just fail on its own.
    await request("POST", "/api/auth/refresh", { refreshToken });

    const attemptWithRotatedToken = await request("POST", "/api/auth/refresh", {
      refreshToken: rotated.body.refreshToken,
    });
    assert.equal(attemptWithRotatedToken.status, 401);
  });

  await t.test("rejects an unknown refresh token", async () => {
    const res = await request("POST", "/api/auth/refresh", { refreshToken: "not-a-real-token" });
    assert.equal(res.status, 401);
  });

  await t.test("rejects a missing refreshToken", async () => {
    const res = await request("POST", "/api/auth/refresh", {});
    assert.equal(res.status, 400);
  });
});

// ---- logout ----

test("POST /api/auth/logout", async (t) => {
  await t.test("revokes the refresh token", async () => {
    const { refreshToken } = await registerAndLogin();
    const logoutRes = await request("POST", "/api/auth/logout", { refreshToken });
    assert.equal(logoutRes.status, 204);

    const refreshRes = await request("POST", "/api/auth/refresh", { refreshToken });
    assert.equal(refreshRes.status, 401);
  });

  await t.test("is idempotent -- logging out twice is still 204", async () => {
    const { refreshToken } = await registerAndLogin();
    await request("POST", "/api/auth/logout", { refreshToken });
    const res = await request("POST", "/api/auth/logout", { refreshToken });
    assert.equal(res.status, 204);
  });

  await t.test("rejects a missing refreshToken", async () => {
    const res = await request("POST", "/api/auth/logout", {});
    assert.equal(res.status, 400);
  });
});

test("unknown route returns 404", async () => {
  const res = await request("GET", "/api/nope");
  assert.equal(res.status, 404);
});
