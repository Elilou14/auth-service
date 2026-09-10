import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";

import { signJwt, verifyJwt } from "../lib/jwt.js";

const SECRET = "test-secret-do-not-use-in-prod";

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

test("signJwt", async (t) => {
  await t.test("produces a 3-part dot-separated string", () => {
    const token = signJwt({ sub: "user-1" }, SECRET);
    assert.equal(token.split(".").length, 3);
  });

  await t.test("rejects a missing/empty secret", () => {
    assert.throws(() => signJwt({ sub: "user-1" }, ""));
    assert.throws(() => signJwt({ sub: "user-1" }, undefined));
  });

  await t.test("rejects a non-object payload", () => {
    assert.throws(() => signJwt("not-an-object", SECRET));
    assert.throws(() => signJwt(null, SECRET));
  });
});

test("verifyJwt: happy path", async (t) => {
  await t.test("returns the original payload plus iat", () => {
    const token = signJwt({ sub: "user-1", role: "admin" }, SECRET);
    const payload = verifyJwt(token, SECRET);
    assert.equal(payload.sub, "user-1");
    assert.equal(payload.role, "admin");
    assert.equal(typeof payload.iat, "number");
  });

  await t.test("includes exp when expiresInSeconds is given", () => {
    const token = signJwt({ sub: "user-1" }, SECRET, { expiresInSeconds: 3600 });
    const payload = verifyJwt(token, SECRET);
    assert.equal(payload.exp, payload.iat + 3600);
  });

  await t.test("omits exp when expiresInSeconds is not given", () => {
    const token = signJwt({ sub: "user-1" }, SECRET);
    const payload = verifyJwt(token, SECRET);
    assert.equal(payload.exp, undefined);
  });
});

test("verifyJwt: rejects tampering and forgery", async (t) => {
  await t.test("wrong secret", () => {
    const token = signJwt({ sub: "user-1" }, SECRET);
    assert.equal(verifyJwt(token, "a-different-secret"), null);
  });

  await t.test("tampered payload (e.g. privilege escalation attempt)", () => {
    const token = signJwt({ sub: "user-1", role: "user" }, SECRET);
    const [header, payload, signature] = token.split(".");
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    const forgedPayload = b64url({ ...decoded, role: "admin" });
    assert.equal(verifyJwt(`${header}.${forgedPayload}.${signature}`, SECRET), null);
  });

  await t.test("tampered signature", () => {
    const token = signJwt({ sub: "user-1" }, SECRET);
    const [header, payload, signature] = token.split(".");
    const flippedSignature = signature.slice(0, -1) + (signature.at(-1) === "A" ? "B" : "A");
    assert.equal(verifyJwt(`${header}.${payload}.${flippedSignature}`, SECRET), null);
  });

  await t.test('rejects alg "none" (classic JWT alg-confusion attack)', () => {
    const header = b64url({ alg: "none", typ: "JWT" });
    const payload = b64url({ sub: "user-1", role: "admin" });
    const forged = `${header}.${payload}.`;
    assert.equal(verifyJwt(forged, SECRET), null);
  });

  await t.test("rejects an alg other than HS256 even with a correct-looking signature", () => {
    const header = b64url({ alg: "HS512", typ: "JWT" });
    const payload = b64url({ sub: "user-1" });
    const signature = crypto.createHmac("sha512", SECRET).update(`${header}.${payload}`).digest("base64url");
    assert.equal(verifyJwt(`${header}.${payload}.${signature}`, SECRET), null);
  });
});

test("verifyJwt: expiry", async (t) => {
  await t.test("rejects an expired token", () => {
    const token = signJwt({ sub: "user-1" }, SECRET, { expiresInSeconds: -1 });
    assert.equal(verifyJwt(token, SECRET), null);
  });

  await t.test("accepts a token that expires in the future", () => {
    const token = signJwt({ sub: "user-1" }, SECRET, { expiresInSeconds: 60 });
    assert.notEqual(verifyJwt(token, SECRET), null);
  });
});

test("verifyJwt: malformed input never throws", async (t) => {
  await t.test("wrong number of segments", () => {
    assert.equal(verifyJwt("not.a.jwt.at.all", SECRET), null);
    assert.equal(verifyJwt("onlyonepart", SECRET), null);
  });

  await t.test("invalid base64/JSON in header or payload", () => {
    assert.equal(verifyJwt("not-base64!.also-not.sig", SECRET), null);
  });

  await t.test("non-string token or secret", () => {
    assert.equal(verifyJwt(undefined, SECRET), null);
    assert.equal(verifyJwt(signJwt({ sub: "user-1" }, SECRET), undefined), null);
  });
});
