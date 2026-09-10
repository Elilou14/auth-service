/**
 * Password hashing via node:crypto's scrypt -- no bcrypt/argon2
 * dependency needed, scrypt is a memory-hard KDF built into Node's
 * standard library and is what OWASP recommends when argon2 isn't
 * available.
 *
 * Encoded as `scrypt$N$r$p$saltHex$hashHex` (PHC-string-inspired):
 * the cost parameters travel with the hash, so `verifyPassword` always
 * uses whatever parameters a given hash was created with even if
 * `DEFAULT_PARAMS` changes later -- old hashes keep verifying
 * correctly after a cost bump, they just don't benefit from it until
 * the user's password is rehashed (e.g. on their next successful
 * login, if the caller chooses to do that -- left to server.js, not
 * this module's concern).
 */

import crypto from "node:crypto";

const DEFAULT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 64 };
const SALT_LENGTH = 16;

function scryptAsync(password, salt, keylen, options) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, options, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

/** maxmem must cover scrypt's ~128*N*r working set; scrypt's own
 * default (32 MiB) already covers DEFAULT_PARAMS, but a caller
 * raising N or r needs this scaled up too. */
function maxmemFor(N, r) {
  return Math.max(32 * 1024 * 1024, 128 * N * r * 2);
}

export async function hashPassword(password, params = DEFAULT_PARAMS) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Password must be a non-empty string.");
  }
  const { N, r, p, keylen } = params;
  const salt = crypto.randomBytes(SALT_LENGTH);
  const derivedKey = await scryptAsync(password, salt, keylen, { N, r, p, maxmem: maxmemFor(N, r) });
  return `scrypt$${N}$${r}$${p}$${salt.toString("hex")}$${derivedKey.toString("hex")}`;
}

export async function verifyPassword(password, stored) {
  if (typeof password !== "string" || typeof stored !== "string") return false;

  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, nStr, rStr, pStr, saltHex, hashHex] = parts;

  const N = Number(nStr);
  const r = Number(rStr);
  const p = Number(pStr);
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return false;

  let salt;
  let expected;
  try {
    salt = Buffer.from(saltHex, "hex");
    expected = Buffer.from(hashHex, "hex");
  } catch {
    return false;
  }
  if (salt.length === 0 || expected.length === 0) return false;

  const derivedKey = await scryptAsync(password, salt, expected.length, { N, r, p, maxmem: maxmemFor(N, r) });
  return derivedKey.length === expected.length && crypto.timingSafeEqual(derivedKey, expected);
}
