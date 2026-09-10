import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { createServer } from "../server.js";

function spyMailer() {
  const resetEmails = [];
  const verificationEmails = [];
  return {
    resetEmails,
    verificationEmails,
    sendPasswordResetEmail: (user, rawToken) => resetEmails.push({ user, rawToken }),
    sendVerificationEmail: (user, rawToken) => verificationEmails.push({ user, rawToken }),
  };
}

async function startServer(overrides = {}) {
  const mailer = spyMailer();
  const server = createServer({
    dbPath: ":memory:",
    jwtSecret: "test-secret-do-not-use-in-prod",
    sendPasswordResetEmail: mailer.sendPasswordResetEmail,
    sendVerificationEmail: mailer.sendVerificationEmail,
    ...overrides,
  });
  await new Promise((resolve) => server.listen(0, resolve));
  const baseUrl = `http://localhost:${server.address().port}`;
  return { server, baseUrl, mailer };
}

function client(baseUrl) {
  return async (method, path, body) => {
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };
}

let userCounter = 0;
function freshCredentials() {
  userCounter += 1;
  return { email: `user${userCounter}@example.com`, password: "correct-horse-1" };
}

let mainServer;
let mainBaseUrl;
let mainMailer;
let request;

before(async () => {
  ({ server: mainServer, baseUrl: mainBaseUrl, mailer: mainMailer } = await startServer());
  request = client(mainBaseUrl);
});

after(() => {
  mainServer.close();
});

// ---- email verification ----

test("registration queues a verification email", async () => {
  const before = mainMailer.verificationEmails.length;
  const creds = freshCredentials();
  await request("POST", "/api/auth/register", creds);
  assert.equal(mainMailer.verificationEmails.length, before + 1);
  assert.equal(mainMailer.verificationEmails.at(-1).user.email, creds.email);
});

test("POST /api/auth/verify-email", async (t) => {
  await t.test("marks the account verified", async () => {
    const creds = freshCredentials();
    const registerRes = await request("POST", "/api/auth/register", creds);
    const { rawToken } = mainMailer.verificationEmails.at(-1);

    const verifyRes = await request("POST", "/api/auth/verify-email", { token: rawToken });
    assert.equal(verifyRes.status, 200);

    const meRes = await fetch(`${mainBaseUrl}/api/me`, {
      headers: { Authorization: `Bearer ${registerRes.body.accessToken}` },
    });
    const me = await meRes.json();
    assert.equal(me.user.emailVerified, true);
  });

  await t.test("rejects an unknown token", async () => {
    const res = await request("POST", "/api/auth/verify-email", { token: "not-a-real-token" });
    assert.equal(res.status, 400);
  });

  await t.test("rejects reusing an already-used token", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);
    const { rawToken } = mainMailer.verificationEmails.at(-1);

    await request("POST", "/api/auth/verify-email", { token: rawToken });
    const secondAttempt = await request("POST", "/api/auth/verify-email", { token: rawToken });
    assert.equal(secondAttempt.status, 400);
  });

  await t.test("rejects an expired token", async () => {
    const { server, baseUrl, mailer } = await startServer({ emailVerificationTtlSeconds: -1 });
    const shortRequest = client(baseUrl);
    const creds = freshCredentials();
    await shortRequest("POST", "/api/auth/register", creds);
    const { rawToken } = mailer.verificationEmails.at(-1);

    const res = await shortRequest("POST", "/api/auth/verify-email", { token: rawToken });
    assert.equal(res.status, 400);
    server.close();
  });

  await t.test("rejects a missing token", async () => {
    const res = await request("POST", "/api/auth/verify-email", {});
    assert.equal(res.status, 400);
  });
});

test("POST /api/auth/resend-verification", async (t) => {
  await t.test("issues a new token and invalidates the previous one", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);
    const originalToken = mainMailer.verificationEmails.at(-1).rawToken;

    const res = await request("POST", "/api/auth/resend-verification", { email: creds.email });
    assert.equal(res.status, 200);
    const newToken = mainMailer.verificationEmails.at(-1).rawToken;
    assert.notEqual(newToken, originalToken);

    const useOldToken = await request("POST", "/api/auth/verify-email", { token: originalToken });
    assert.equal(useOldToken.status, 400);

    const useNewToken = await request("POST", "/api/auth/verify-email", { token: newToken });
    assert.equal(useNewToken.status, 200);
  });

  await t.test("returns 200 for an unknown email without sending anything", async () => {
    const before = mainMailer.verificationEmails.length;
    const res = await request("POST", "/api/auth/resend-verification", { email: "nobody@example.com" });
    assert.equal(res.status, 200);
    assert.equal(mainMailer.verificationEmails.length, before);
  });

  await t.test("returns 200 for an already-verified user without sending anything", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);
    await request("POST", "/api/auth/verify-email", { token: mainMailer.verificationEmails.at(-1).rawToken });

    const before = mainMailer.verificationEmails.length;
    const res = await request("POST", "/api/auth/resend-verification", { email: creds.email });
    assert.equal(res.status, 200);
    assert.equal(mainMailer.verificationEmails.length, before);
  });

  await t.test("rejects a malformed email", async () => {
    const res = await request("POST", "/api/auth/resend-verification", { email: "not-an-email" });
    assert.equal(res.status, 400);
  });
});

// ---- password reset ----

test("POST /api/auth/forgot-password", async (t) => {
  await t.test("queues a reset email for a known address", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);

    const before = mainMailer.resetEmails.length;
    const res = await request("POST", "/api/auth/forgot-password", { email: creds.email });
    assert.equal(res.status, 200);
    assert.equal(mainMailer.resetEmails.length, before + 1);
  });

  await t.test("returns 200 for an unknown address without sending anything", async () => {
    const before = mainMailer.resetEmails.length;
    const res = await request("POST", "/api/auth/forgot-password", { email: "nobody@example.com" });
    assert.equal(res.status, 200);
    assert.equal(mainMailer.resetEmails.length, before);
  });

  await t.test("both responses carry the same generic message", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);
    const known = await request("POST", "/api/auth/forgot-password", { email: creds.email });
    const unknown = await request("POST", "/api/auth/forgot-password", { email: "nobody2@example.com" });
    assert.equal(known.body.message, unknown.body.message);
  });

  await t.test("rejects a malformed email", async () => {
    const res = await request("POST", "/api/auth/forgot-password", { email: "not-an-email" });
    assert.equal(res.status, 400);
  });

  await t.test("requesting again invalidates the previous reset token", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);
    await request("POST", "/api/auth/forgot-password", { email: creds.email });
    const firstToken = mainMailer.resetEmails.at(-1).rawToken;

    await request("POST", "/api/auth/forgot-password", { email: creds.email });

    const res = await request("POST", "/api/auth/reset-password", { token: firstToken, newPassword: "new-pass-1" });
    assert.equal(res.status, 400);
  });
});

test("POST /api/auth/reset-password", async (t) => {
  await t.test("changes the password and revokes existing refresh tokens", async () => {
    const creds = freshCredentials();
    const registerRes = await request("POST", "/api/auth/register", creds);
    await request("POST", "/api/auth/forgot-password", { email: creds.email });
    const { rawToken } = mainMailer.resetEmails.at(-1);

    const resetRes = await request("POST", "/api/auth/reset-password", { token: rawToken, newPassword: "new-pass-1" });
    assert.equal(resetRes.status, 200);

    const oldPasswordLogin = await request("POST", "/api/auth/login", creds);
    assert.equal(oldPasswordLogin.status, 401);

    const newPasswordLogin = await request("POST", "/api/auth/login", { email: creds.email, password: "new-pass-1" });
    assert.equal(newPasswordLogin.status, 200);

    const oldRefresh = await request("POST", "/api/auth/refresh", { refreshToken: registerRes.body.refreshToken });
    assert.equal(oldRefresh.status, 401);
  });

  await t.test("rejects a weak new password", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);
    await request("POST", "/api/auth/forgot-password", { email: creds.email });
    const { rawToken } = mainMailer.resetEmails.at(-1);

    const res = await request("POST", "/api/auth/reset-password", { token: rawToken, newPassword: "weak" });
    assert.equal(res.status, 400);
  });

  await t.test("rejects an unknown token", async () => {
    const res = await request("POST", "/api/auth/reset-password", { token: "not-a-real-token", newPassword: "new-pass-1" });
    assert.equal(res.status, 400);
  });

  await t.test("rejects reusing an already-used token", async () => {
    const creds = freshCredentials();
    await request("POST", "/api/auth/register", creds);
    await request("POST", "/api/auth/forgot-password", { email: creds.email });
    const { rawToken } = mainMailer.resetEmails.at(-1);

    await request("POST", "/api/auth/reset-password", { token: rawToken, newPassword: "new-pass-1" });
    const secondAttempt = await request("POST", "/api/auth/reset-password", { token: rawToken, newPassword: "another-pass-2" });
    assert.equal(secondAttempt.status, 400);
  });

  await t.test("rejects an expired token", async () => {
    const { server, baseUrl, mailer } = await startServer({ passwordResetTtlSeconds: -1 });
    const shortRequest = client(baseUrl);
    const creds = freshCredentials();
    await shortRequest("POST", "/api/auth/register", creds);
    await shortRequest("POST", "/api/auth/forgot-password", { email: creds.email });
    const { rawToken } = mailer.resetEmails.at(-1);

    const res = await shortRequest("POST", "/api/auth/reset-password", { token: rawToken, newPassword: "new-pass-1" });
    assert.equal(res.status, 400);
    server.close();
  });

  await t.test("rejects a missing token", async () => {
    const res = await request("POST", "/api/auth/reset-password", { newPassword: "new-pass-1" });
    assert.equal(res.status, 400);
  });
});
