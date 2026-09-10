import assert from "node:assert/strict";
import { test } from "node:test";

import { hashPassword, verifyPassword } from "../lib/passwords.js";

// Lower cost than the module's default so the suite stays fast; one
// test below confirms the real default still round-trips correctly.
const FAST_PARAMS = { N: 1024, r: 8, p: 1, keylen: 64 };

test("hashPassword", async (t) => {
  await t.test("produces a scrypt-prefixed, 6-part encoded string", async () => {
    const hash = await hashPassword("hunter2!", FAST_PARAMS);
    const parts = hash.split("$");
    assert.equal(parts.length, 6);
    assert.equal(parts[0], "scrypt");
  });

  await t.test("two hashes of the same password differ (random salt)", async () => {
    const a = await hashPassword("hunter2!", FAST_PARAMS);
    const b = await hashPassword("hunter2!", FAST_PARAMS);
    assert.notEqual(a, b);
  });

  await t.test("rejects an empty password", async () => {
    await assert.rejects(() => hashPassword("", FAST_PARAMS));
  });

  await t.test("rejects a non-string password", async () => {
    await assert.rejects(() => hashPassword(undefined, FAST_PARAMS));
  });
});

test("verifyPassword", async (t) => {
  await t.test("true for the correct password", async () => {
    const hash = await hashPassword("hunter2!", FAST_PARAMS);
    assert.equal(await verifyPassword("hunter2!", hash), true);
  });

  await t.test("false for an incorrect password", async () => {
    const hash = await hashPassword("hunter2!", FAST_PARAMS);
    assert.equal(await verifyPassword("wrong-password", hash), false);
  });

  await t.test("false for a malformed stored hash", async () => {
    assert.equal(await verifyPassword("hunter2!", "not-a-real-hash"), false);
    assert.equal(await verifyPassword("hunter2!", "scrypt$16384$8$1$onlyfourparts"), false);
    assert.equal(await verifyPassword("hunter2!", "bcrypt$10$abc$def$salt$hash"), false);
  });

  await t.test("false for non-string arguments", async () => {
    assert.equal(await verifyPassword(undefined, "scrypt$16384$8$1$aa$bb"), false);
    const hash = await hashPassword("hunter2!", FAST_PARAMS);
    assert.equal(await verifyPassword(hash, undefined), false);
  });

  await t.test("false when the salt/hash hex is invalid", async () => {
    assert.equal(await verifyPassword("hunter2!", "scrypt$1024$8$1$zz$zz"), false);
  });

  await t.test("round-trips with the module's real default cost parameters", async () => {
    const hash = await hashPassword("a-real-password1");
    assert.equal(await verifyPassword("a-real-password1", hash), true);
    assert.equal(await verifyPassword("wrong", hash), false);
  });
});
