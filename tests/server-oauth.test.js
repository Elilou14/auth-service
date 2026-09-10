import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { createServer } from "../server.js";
import { startMockOAuthProvider } from "./helpers/mock-oauth-provider.js";

let mockProvider;
let server;
let baseUrl;

before(async () => {
  mockProvider = await startMockOAuthProvider();
  server = createServer({
    dbPath: ":memory:",
    jwtSecret: "test-secret-do-not-use-in-prod",
    oauthProviders: { mock: mockProvider.providerConfig() },
  });
  await new Promise((resolve) => server.listen(0, resolve));
  baseUrl = `http://localhost:${server.address().port}`;
});

after(() => {
  server.close();
  mockProvider.server.close();
});

async function getAuthorizeRedirect() {
  const res = await fetch(`${baseUrl}/api/auth/oauth/mock`, { redirect: "manual" });
  assert.equal(res.status, 302);
  return new URL(res.headers.get("location"));
}

async function getValidState() {
  const location = await getAuthorizeRedirect();
  return location.searchParams.get("state");
}

let codeCounter = 0;
function freshCode() {
  codeCounter += 1;
  return `code-${codeCounter}`;
}

test("GET /api/auth/oauth/:provider", async (t) => {
  await t.test("redirects to the provider's authorization URL with the expected params", async () => {
    const location = await getAuthorizeRedirect();
    assert.equal(location.origin + location.pathname, `${mockProvider.baseUrl}/oauth/authorize`);
    assert.equal(location.searchParams.get("client_id"), "mock-client-id");
    assert.equal(location.searchParams.get("redirect_uri"), `${mockProvider.baseUrl}/callback`);
    assert.equal(location.searchParams.get("response_type"), "code");
    assert.ok(location.searchParams.get("state"));
  });

  await t.test("404s for a provider that isn't configured", async () => {
    const res = await fetch(`${baseUrl}/api/auth/oauth/not-configured`, { redirect: "manual" });
    assert.equal(res.status, 404);
  });
});

test("GET /api/auth/oauth/:provider/callback", async (t) => {
  await t.test("creates a new user and redirects with tokens in the fragment", async () => {
    const state = await getValidState();
    const code = freshCode();
    mockProvider.setProfileForCode(code, { id: "ext-1", email: "oauthuser1@example.com" });

    const res = await fetch(`${baseUrl}/api/auth/oauth/mock/callback?code=${code}&state=${state}`, {
      redirect: "manual",
    });
    assert.equal(res.status, 302);

    const location = res.headers.get("location");
    assert.ok(location.startsWith("/oauth-callback.html#"));

    const fragment = new URLSearchParams(location.split("#")[1]);
    assert.ok(fragment.get("access_token"));
    assert.ok(fragment.get("refresh_token"));

    const meRes = await fetch(`${baseUrl}/api/me`, {
      headers: { Authorization: `Bearer ${fragment.get("access_token")}` },
    });
    const me = await meRes.json();
    assert.equal(me.user.email, "oauthuser1@example.com");
    assert.equal(me.user.emailVerified, true); // the provider already verified it
  });

  await t.test("signing in again with the same external account returns the same local user", async () => {
    const firstState = await getValidState();
    const firstCode = freshCode();
    mockProvider.setProfileForCode(firstCode, { id: "ext-2", email: "oauthuser2@example.com" });
    const firstRes = await fetch(`${baseUrl}/api/auth/oauth/mock/callback?code=${firstCode}&state=${firstState}`, {
      redirect: "manual",
    });
    const firstToken = new URLSearchParams(locationFragment(firstRes)).get("access_token");
    const firstMe = await (await fetch(`${baseUrl}/api/me`, { headers: { Authorization: `Bearer ${firstToken}` } })).json();

    const secondState = await getValidState();
    const secondCode = freshCode();
    mockProvider.setProfileForCode(secondCode, { id: "ext-2", email: "oauthuser2@example.com" });
    const secondRes = await fetch(`${baseUrl}/api/auth/oauth/mock/callback?code=${secondCode}&state=${secondState}`, {
      redirect: "manual",
    });
    const secondToken = new URLSearchParams(locationFragment(secondRes)).get("access_token");
    const secondMe = await (await fetch(`${baseUrl}/api/me`, { headers: { Authorization: `Bearer ${secondToken}` } })).json();

    assert.equal(secondMe.user.id, firstMe.user.id);
  });

  await t.test("links to an existing password account with the same email instead of creating a new one", async () => {
    const registerRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "linked-user@example.com", password: "correct-horse-1" }),
    });
    const { user: existingUser } = await registerRes.json();

    const state = await getValidState();
    const code = freshCode();
    mockProvider.setProfileForCode(code, { id: "ext-linked", email: "linked-user@example.com" });
    const callbackRes = await fetch(`${baseUrl}/api/auth/oauth/mock/callback?code=${code}&state=${state}`, {
      redirect: "manual",
    });
    const token = new URLSearchParams(locationFragment(callbackRes)).get("access_token");
    const me = await (await fetch(`${baseUrl}/api/me`, { headers: { Authorization: `Bearer ${token}` } })).json();

    assert.equal(me.user.id, existingUser.id);

    // The password still works -- linking didn't disturb the existing account.
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "linked-user@example.com", password: "correct-horse-1" }),
    });
    assert.equal(loginRes.status, 200);
  });

  await t.test("rejects a missing or invalid state", async () => {
    const code = freshCode();
    mockProvider.setProfileForCode(code, { id: "ext-3", email: "oauthuser3@example.com" });

    const noState = await fetch(`${baseUrl}/api/auth/oauth/mock/callback?code=${code}`, { redirect: "manual" });
    assert.equal(noState.status, 400);

    const badState = await fetch(`${baseUrl}/api/auth/oauth/mock/callback?code=${code}&state=garbage`, {
      redirect: "manual",
    });
    assert.equal(badState.status, 400);
  });

  await t.test("rejects a missing code", async () => {
    const state = await getValidState();
    const res = await fetch(`${baseUrl}/api/auth/oauth/mock/callback?state=${state}`, { redirect: "manual" });
    assert.equal(res.status, 400);
  });

  await t.test("surfaces a failed token exchange as an error rather than issuing tokens", async () => {
    const state = await getValidState();
    const res = await fetch(`${baseUrl}/api/auth/oauth/mock/callback?code=never-registered&state=${state}`, {
      redirect: "manual",
    });
    assert.notEqual(res.status, 302);
  });

  await t.test("404s for a provider that isn't configured", async () => {
    const state = await getValidState();
    const res = await fetch(`${baseUrl}/api/auth/oauth/not-configured/callback?code=x&state=${state}`, {
      redirect: "manual",
    });
    assert.equal(res.status, 404);
  });
});

function locationFragment(res) {
  return res.headers.get("location").split("#")[1];
}
