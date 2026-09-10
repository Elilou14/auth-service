/**
 * Single-use, high-entropy tokens for email verification and
 * password reset. The raw token is what gets emailed to the user and
 * is never persisted -- only `hashToken(raw)` is stored, so a
 * database leak doesn't hand out usable tokens, the same reasoning as
 * never storing plaintext passwords. Unlike passwords.js, this uses
 * a fast hash (SHA-256, not scrypt): these tokens already have 256
 * bits of entropy from crypto.randomBytes, so there's no guessing
 * attack for a slow KDF to defend against -- a fast hash just needs
 * to not be reversible, which SHA-256 already isn't.
 *
 * Expiry is a plain epoch-milliseconds number, so it stores directly
 * as a SQLite INTEGER with no parsing on the way back out.
 */

import crypto from "node:crypto";

const DEFAULT_TOKEN_BYTES = 32;

export function generateToken(byteLength = DEFAULT_TOKEN_BYTES) {
  return crypto.randomBytes(byteLength).toString("base64url");
}

export function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

/** Timing-safe check that `token`'s hash matches the stored `hash`.
 * (SHA-256 of a random 256-bit value isn't guessable either way, so
 * this is defense-in-depth rather than closing an exploitable gap --
 * cheap to do right, so it's done right.) */
export function tokensMatch(token, hash) {
  if (typeof token !== "string" || typeof hash !== "string") return false;
  const actual = Buffer.from(hashToken(token), "hex");
  const expected = Buffer.from(hash, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function expiresAt(ttlSeconds) {
  return Date.now() + ttlSeconds * 1000;
}

export function isExpired(expiresAtMs) {
  return typeof expiresAtMs !== "number" || expiresAtMs <= Date.now();
}
