/**
 * Pure input validation -- no I/O, no hashing, no database. Shared by
 * the register, reset-password and (indirectly, via password
 * strength) login-adjacent endpoints in server.js.
 *
 * Password policy is deliberately just length + a letter + a digit,
 * not composition rules (uppercase/symbol requirements) -- NIST
 * 800-63B's guidance is that length is what actually matters for
 * resisting guessing/cracking, and composition rules mostly just
 * push users toward predictable substitutions ("password" ->
 * "Passw0rd!"). The max length exists to keep scrypt's cost bounded
 * against a client submitting a multi-megabyte "password".
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_LENGTH = 254; // RFC 5321
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

export function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

export function validateEmail(email) {
  if (typeof email !== "string") return { valid: false, reason: "Email is required." };
  const trimmed = email.trim();
  if (!trimmed) return { valid: false, reason: "Email is required." };
  if (trimmed.length > MAX_EMAIL_LENGTH) return { valid: false, reason: "Email is too long." };
  if (!EMAIL_RE.test(trimmed)) return { valid: false, reason: "Email format is invalid." };
  return { valid: true };
}

export function validatePassword(password) {
  if (typeof password !== "string" || password.length === 0) {
    return { valid: false, reason: "Password is required." };
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return { valid: false, reason: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` };
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    return { valid: false, reason: `Password must be at most ${MAX_PASSWORD_LENGTH} characters.` };
  }
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
    return { valid: false, reason: "Password must contain at least one letter and one number." };
  }
  return { valid: true };
}
