import assert from "node:assert/strict";
import { test } from "node:test";

import { expiresAt, generateToken, hashToken, isExpired, tokensMatch } from "../lib/tokens.js";

test("generateToken", async (t) => {
  await t.test("produces a URL-safe string with no padding characters", () => {
    const token = generateToken();
    assert.match(token, /^[A-Za-z0-9_-]+$/);
  });

  await t.test("two calls produce different tokens", () => {
    assert.notEqual(generateToken(), generateToken());
  });

  await t.test("longer byte length produces a longer token", () => {
    assert.ok(generateToken(64).length > generateToken(16).length);
  });
});

test("hashToken", async (t) => {
  await t.test("is deterministic", () => {
    const token = generateToken();
    assert.equal(hashToken(token), hashToken(token));
  });

  await t.test("different tokens hash differently", () => {
    assert.notEqual(hashToken("token-a"), hashToken("token-b"));
  });

  await t.test("produces a 64-character hex string (SHA-256)", () => {
    assert.match(hashToken("anything"), /^[0-9a-f]{64}$/);
  });
});

test("tokensMatch", async (t) => {
  await t.test("true for the token that produced the stored hash", () => {
    const token = generateToken();
    assert.equal(tokensMatch(token, hashToken(token)), true);
  });

  await t.test("false for a different token", () => {
    const token = generateToken();
    assert.equal(tokensMatch("some-other-token", hashToken(token)), false);
  });

  await t.test("false for non-string arguments", () => {
    assert.equal(tokensMatch(undefined, hashToken("x")), false);
    assert.equal(tokensMatch("x", undefined), false);
  });
});

test("expiresAt / isExpired", async (t) => {
  await t.test("a future expiry is not expired", () => {
    assert.equal(isExpired(expiresAt(3600)), false);
  });

  await t.test("a past expiry is expired", () => {
    assert.equal(isExpired(expiresAt(-1)), true);
  });

  await t.test("a non-number is treated as expired", () => {
    assert.equal(isExpired(undefined), true);
    assert.equal(isExpired("not-a-number"), true);
  });
});
