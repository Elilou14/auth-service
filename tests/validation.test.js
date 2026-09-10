import assert from "node:assert/strict";
import { test } from "node:test";

import { normalizeEmail, validateEmail, validatePassword } from "../lib/validation.js";

test("normalizeEmail", async (t) => {
  await t.test("lowercases and trims", () => {
    assert.equal(normalizeEmail("  Alice@Example.com  "), "alice@example.com");
  });
});

test("validateEmail", async (t) => {
  await t.test("accepts a well-formed email", () => {
    assert.deepEqual(validateEmail("alice@example.com"), { valid: true });
  });

  await t.test("rejects an empty or whitespace-only email", () => {
    assert.equal(validateEmail("").valid, false);
    assert.equal(validateEmail("   ").valid, false);
  });

  await t.test("rejects a non-string", () => {
    assert.equal(validateEmail(undefined).valid, false);
    assert.equal(validateEmail(null).valid, false);
  });

  await t.test("rejects missing @ or missing domain dot", () => {
    assert.equal(validateEmail("alice.example.com").valid, false);
    assert.equal(validateEmail("alice@examplecom").valid, false);
  });

  await t.test("rejects an email containing whitespace", () => {
    assert.equal(validateEmail("ali ce@example.com").valid, false);
  });

  await t.test("rejects an email over 254 characters", () => {
    const long = `${"a".repeat(250)}@b.co`;
    assert.equal(validateEmail(long).valid, false);
  });
});

test("validatePassword", async (t) => {
  await t.test("accepts a password with a letter and a digit at minimum length", () => {
    assert.deepEqual(validatePassword("abcdef12"), { valid: true });
  });

  await t.test("rejects an empty password", () => {
    assert.equal(validatePassword("").valid, false);
  });

  await t.test("rejects a non-string", () => {
    assert.equal(validatePassword(undefined).valid, false);
  });

  await t.test("rejects a password shorter than 8 characters", () => {
    assert.equal(validatePassword("abc123").valid, false);
  });

  await t.test("rejects a password longer than 128 characters", () => {
    assert.equal(validatePassword(`a1${"x".repeat(127)}`).valid, false);
  });

  await t.test("rejects a password with no letter", () => {
    assert.equal(validatePassword("12345678").valid, false);
  });

  await t.test("rejects a password with no digit", () => {
    assert.equal(validatePassword("abcdefgh").valid, false);
  });
});
