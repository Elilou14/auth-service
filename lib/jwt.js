/**
 * A minimal, dependency-free JWT implementation -- HS256 only, on
 * purpose. Supporting multiple algorithms (especially letting the
 * token itself declare "none" or an asymmetric alg the caller didn't
 * ask for) is exactly how the classic JWT "alg confusion" attacks
 * work; verifyJwt hardcodes HS256 and ignores whatever `alg` the
 * token claims if it isn't that.
 *
 * A token is `base64url(header).base64url(payload).base64url(hmac)`,
 * same shape as every other JWT library -- this one just doesn't
 * pull in a package to produce it.
 */

import crypto from "node:crypto";

function base64urlEncode(input) {
  return Buffer.from(input).toString("base64url");
}

function base64urlDecodeToString(input) {
  return Buffer.from(input, "base64url").toString("utf8");
}

function hmacSha256(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

/** `payload` is merged with `iat` (always) and `exp` (only if
 * `expiresInSeconds` is given) before encoding. */
export function signJwt(payload, secret, { expiresInSeconds } = {}) {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new Error("JWT secret must be a non-empty string.");
  }
  if (payload === null || typeof payload !== "object") {
    throw new Error("JWT payload must be an object.");
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: nowSeconds };
  if (expiresInSeconds !== undefined) {
    fullPayload.exp = nowSeconds + expiresInSeconds;
  }

  const encodedHeader = base64urlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const encodedPayload = base64urlEncode(JSON.stringify(fullPayload));
  const signature = hmacSha256(`${encodedHeader}.${encodedPayload}`, secret);

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/** Returns the decoded payload if `token` has a valid HS256 signature
 * for `secret` and hasn't expired, otherwise null -- never throws on
 * malformed input, so callers can treat null as "unauthenticated"
 * without a try/catch. */
export function verifyJwt(token, secret) {
  if (typeof token !== "string" || typeof secret !== "string") return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts;

  let header;
  let payload;
  try {
    header = JSON.parse(base64urlDecodeToString(encodedHeader));
    payload = JSON.parse(base64urlDecodeToString(encodedPayload));
  } catch {
    return null;
  }

  if (!header || header.alg !== "HS256") return null; // rejects "none" and every other alg

  const expected = Buffer.from(hmacSha256(`${encodedHeader}.${encodedPayload}`, secret));
  const actual = Buffer.from(signature);
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    return null;
  }

  if (typeof payload.exp === "number" && Math.floor(Date.now() / 1000) >= payload.exp) {
    return null; // expired
  }

  return payload;
}
