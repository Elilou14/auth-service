import assert from "node:assert/strict";
import { test } from "node:test";

import {
  PROVIDERS,
  buildAuthorizationUrl,
  exchangeCodeForToken,
  fetchUserProfile,
  generateState,
  getOAuthIdentity,
  resolveProvider,
} from "../lib/oauth.js";

function fakeResponse(status, jsonBody) {
  return { ok: status >= 200 && status < 300, status, json: async () => jsonBody };
}

/** Records every call and returns queued responses in order. */
function fakeFetch(responses) {
  const calls = [];
  const queue = [...responses];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return queue.shift();
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

const CREDENTIALS = { clientId: "client-123", clientSecret: "secret-456", redirectUri: "https://app.test/callback" };

test("resolveProvider", async (t) => {
  await t.test("merges a known preset with the given credentials", () => {
    const provider = resolveProvider("github", CREDENTIALS);
    assert.equal(provider.clientId, "client-123");
    assert.equal(provider.authorizationUrl, PROVIDERS.github.authorizationUrl);
  });

  await t.test("throws for an unknown provider name", () => {
    assert.throws(() => resolveProvider("not-a-provider", CREDENTIALS));
  });
});

test("generateState", async (t) => {
  await t.test("produces different, URL-safe values", () => {
    const a = generateState();
    const b = generateState();
    assert.notEqual(a, b);
    assert.match(a, /^[A-Za-z0-9_-]+$/);
  });
});

test("buildAuthorizationUrl", async (t) => {
  await t.test("includes client_id, redirect_uri, response_type, scope and state", () => {
    const provider = resolveProvider("github", CREDENTIALS);
    const url = new URL(buildAuthorizationUrl(provider, { state: "xyz" }));
    assert.equal(url.origin + url.pathname, "https://github.com/login/oauth/authorize");
    assert.equal(url.searchParams.get("client_id"), "client-123");
    assert.equal(url.searchParams.get("redirect_uri"), "https://app.test/callback");
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("scope"), PROVIDERS.github.scope);
    assert.equal(url.searchParams.get("state"), "xyz");
  });
});

test("exchangeCodeForToken", async (t) => {
  await t.test("returns the token response and posts the expected form fields", async () => {
    const provider = resolveProvider("github", CREDENTIALS);
    const fetchImpl = fakeFetch([fakeResponse(200, { access_token: "tok-1", token_type: "bearer" })]);

    const result = await exchangeCodeForToken(provider, "auth-code-1", { fetchImpl });

    assert.equal(result.access_token, "tok-1");
    assert.equal(fetchImpl.calls.length, 1);
    const { url, options } = fetchImpl.calls[0];
    assert.equal(url, provider.tokenUrl);
    assert.equal(options.method, "POST");
    const sentBody = new URLSearchParams(options.body.toString());
    assert.equal(sentBody.get("client_id"), "client-123");
    assert.equal(sentBody.get("client_secret"), "secret-456");
    assert.equal(sentBody.get("code"), "auth-code-1");
    assert.equal(sentBody.get("grant_type"), "authorization_code");
  });

  await t.test("throws on a non-OK response", async () => {
    const provider = resolveProvider("github", CREDENTIALS);
    const fetchImpl = fakeFetch([fakeResponse(401, { error: "bad_verification_code" })]);
    await assert.rejects(() => exchangeCodeForToken(provider, "bad-code", { fetchImpl }));
  });

  await t.test("throws when the response has no access_token", async () => {
    const provider = resolveProvider("github", CREDENTIALS);
    const fetchImpl = fakeFetch([fakeResponse(200, { error: "invalid_grant" })]);
    await assert.rejects(() => exchangeCodeForToken(provider, "code", { fetchImpl }));
  });
});

test("fetchUserProfile", async (t) => {
  await t.test("returns the profile and sends a bearer Authorization header", async () => {
    const provider = resolveProvider("github", CREDENTIALS);
    const fetchImpl = fakeFetch([fakeResponse(200, { id: 42, email: "a@b.com" })]);

    const profile = await fetchUserProfile(provider, "tok-1", { fetchImpl });

    assert.equal(profile.id, 42);
    assert.equal(fetchImpl.calls[0].options.headers.Authorization, "Bearer tok-1");
  });

  await t.test("throws on a non-OK response", async () => {
    const provider = resolveProvider("github", CREDENTIALS);
    const fetchImpl = fakeFetch([fakeResponse(403, { message: "forbidden" })]);
    await assert.rejects(() => fetchUserProfile(provider, "tok-1", { fetchImpl }));
  });
});

test("getOAuthIdentity", async (t) => {
  await t.test("chains token exchange and profile fetch into {providerAccountId, email}", async () => {
    const provider = resolveProvider("github", CREDENTIALS);
    const fetchImpl = fakeFetch([
      fakeResponse(200, { access_token: "tok-1" }),
      fakeResponse(200, { id: 42, email: "a@b.com" }),
    ]);

    const identity = await getOAuthIdentity(provider, "auth-code", { fetchImpl });
    assert.deepEqual(identity, { providerAccountId: "42", email: "a@b.com" });
  });

  await t.test("throws when the mapped profile has no account id", async () => {
    const provider = resolveProvider("github", { ...CREDENTIALS, mapProfile: () => ({ email: "a@b.com" }) });
    const fetchImpl = fakeFetch([fakeResponse(200, { access_token: "tok-1" }), fakeResponse(200, {})]);
    await assert.rejects(() => getOAuthIdentity(provider, "auth-code", { fetchImpl }));
  });
});

test("provider profile mapping", async (t) => {
  await t.test("github: numeric id becomes a string providerAccountId", () => {
    assert.deepEqual(PROVIDERS.github.mapProfile({ id: 999, email: "a@b.com" }), {
      providerAccountId: "999",
      email: "a@b.com",
    });
  });

  await t.test("google: sub is the providerAccountId", () => {
    assert.deepEqual(PROVIDERS.google.mapProfile({ sub: "google-abc", email: "a@b.com" }), {
      providerAccountId: "google-abc",
      email: "a@b.com",
    });
  });
});
