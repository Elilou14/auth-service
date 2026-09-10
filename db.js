/**
 * SQLite persistence (node:sqlite, no dependency) for everything the
 * auth brick needs: users, refresh tokens (rotated + revocable),
 * password-reset and email-verification tokens (single-use, stored
 * only as a hash -- see lib/tokens.js), and OAuth account links.
 *
 * Every *TokenHash column stores lib/tokens.js's hashToken() output,
 * never a raw token. passwordHash can be NULL: an OAuth-only account
 * (no password ever set) is a legitimate state, not an error.
 */

import crypto from "node:crypto";
import { DatabaseSync } from "node:sqlite";

export function openDb(path = "auth.sqlite") {
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      passwordHash TEXT,
      emailVerified INTEGER NOT NULL DEFAULT 0,
      createdAt INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      tokenHash TEXT NOT NULL UNIQUE,
      expiresAt INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      createdAt INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      tokenHash TEXT NOT NULL UNIQUE,
      expiresAt INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      createdAt INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS email_verification_tokens (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      tokenHash TEXT NOT NULL UNIQUE,
      expiresAt INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      createdAt INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_accounts (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      provider TEXT NOT NULL,
      providerAccountId TEXT NOT NULL,
      createdAt INTEGER NOT NULL,
      UNIQUE(provider, providerAccountId)
    );
  `);
  return db;
}

function defaultId() {
  return crypto.randomUUID();
}

function rowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.passwordHash,
    emailVerified: Boolean(row.emailVerified),
    createdAt: row.createdAt,
  };
}

// ---- users ----

export function createUser(db, { email, passwordHash = null }, idGenerator = defaultId) {
  const user = { id: idGenerator(), email, passwordHash, emailVerified: false, createdAt: Date.now() };
  db.prepare(
    "INSERT INTO users (id, email, passwordHash, emailVerified, createdAt) VALUES (?, ?, ?, 0, ?)"
  ).run(user.id, user.email, user.passwordHash, user.createdAt);
  return user;
}

export function findUserByEmail(db, email) {
  return rowToUser(db.prepare("SELECT * FROM users WHERE email = ?").get(email));
}

export function findUserById(db, id) {
  return rowToUser(db.prepare("SELECT * FROM users WHERE id = ?").get(id));
}

export function setEmailVerified(db, userId) {
  const { changes } = db.prepare("UPDATE users SET emailVerified = 1 WHERE id = ?").run(userId);
  return changes > 0;
}

export function updatePasswordHash(db, userId, passwordHash) {
  const { changes } = db.prepare("UPDATE users SET passwordHash = ? WHERE id = ?").run(passwordHash, userId);
  return changes > 0;
}

// ---- refresh tokens ----

export function insertRefreshToken(db, { userId, tokenHash, expiresAt }, idGenerator = defaultId) {
  const row = { id: idGenerator(), userId, tokenHash, expiresAt, createdAt: Date.now() };
  db.prepare(
    "INSERT INTO refresh_tokens (id, userId, tokenHash, expiresAt, revoked, createdAt) VALUES (?, ?, ?, ?, 0, ?)"
  ).run(row.id, row.userId, row.tokenHash, row.expiresAt, row.createdAt);
  return row;
}

export function findRefreshToken(db, tokenHash) {
  const row = db.prepare("SELECT * FROM refresh_tokens WHERE tokenHash = ?").get(tokenHash);
  if (!row) return null;
  return { ...row, revoked: Boolean(row.revoked) };
}

export function revokeRefreshToken(db, tokenHash) {
  const { changes } = db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE tokenHash = ?").run(tokenHash);
  return changes > 0;
}

/** Used on password reset (and available to call on any "this
 * account may be compromised" event): every refresh token issued to
 * this user stops working, everywhere they were logged in. */
export function revokeAllRefreshTokensForUser(db, userId) {
  const { changes } = db
    .prepare("UPDATE refresh_tokens SET revoked = 1 WHERE userId = ? AND revoked = 0")
    .run(userId);
  return changes;
}

// ---- password reset tokens ----

export function insertPasswordResetToken(db, { userId, tokenHash, expiresAt }, idGenerator = defaultId) {
  const row = { id: idGenerator(), userId, tokenHash, expiresAt, createdAt: Date.now() };
  db.prepare(
    "INSERT INTO password_reset_tokens (id, userId, tokenHash, expiresAt, used, createdAt) VALUES (?, ?, ?, ?, 0, ?)"
  ).run(row.id, row.userId, row.tokenHash, row.expiresAt, row.createdAt);
  return row;
}

export function findPasswordResetToken(db, tokenHash) {
  const row = db.prepare("SELECT * FROM password_reset_tokens WHERE tokenHash = ?").get(tokenHash);
  if (!row) return null;
  return { ...row, used: Boolean(row.used) };
}

export function markPasswordResetTokenUsed(db, tokenHash) {
  const { changes } = db
    .prepare("UPDATE password_reset_tokens SET used = 1 WHERE tokenHash = ?")
    .run(tokenHash);
  return changes > 0;
}

/** Called before issuing a new reset token: an old, unused token for
 * this user should stop working once a fresher one exists, so a
 * leaked-then-rotated-away token can't still be redeemed. */
export function invalidatePasswordResetTokensForUser(db, userId) {
  const { changes } = db
    .prepare("UPDATE password_reset_tokens SET used = 1 WHERE userId = ? AND used = 0")
    .run(userId);
  return changes;
}

// ---- email verification tokens ----

export function insertEmailVerificationToken(db, { userId, tokenHash, expiresAt }, idGenerator = defaultId) {
  const row = { id: idGenerator(), userId, tokenHash, expiresAt, createdAt: Date.now() };
  db.prepare(
    "INSERT INTO email_verification_tokens (id, userId, tokenHash, expiresAt, used, createdAt) VALUES (?, ?, ?, ?, 0, ?)"
  ).run(row.id, row.userId, row.tokenHash, row.expiresAt, row.createdAt);
  return row;
}

export function findEmailVerificationToken(db, tokenHash) {
  const row = db.prepare("SELECT * FROM email_verification_tokens WHERE tokenHash = ?").get(tokenHash);
  if (!row) return null;
  return { ...row, used: Boolean(row.used) };
}

export function markEmailVerificationTokenUsed(db, tokenHash) {
  const { changes } = db
    .prepare("UPDATE email_verification_tokens SET used = 1 WHERE tokenHash = ?")
    .run(tokenHash);
  return changes > 0;
}

export function invalidateEmailVerificationTokensForUser(db, userId) {
  const { changes } = db
    .prepare("UPDATE email_verification_tokens SET used = 1 WHERE userId = ? AND used = 0")
    .run(userId);
  return changes;
}

// ---- OAuth accounts ----

export function linkOAuthAccount(db, { userId, provider, providerAccountId }, idGenerator = defaultId) {
  const row = { id: idGenerator(), userId, provider, providerAccountId, createdAt: Date.now() };
  db.prepare(
    "INSERT INTO oauth_accounts (id, userId, provider, providerAccountId, createdAt) VALUES (?, ?, ?, ?, ?)"
  ).run(row.id, row.userId, row.provider, row.providerAccountId, row.createdAt);
  return row;
}

export function findUserByOAuthAccount(db, provider, providerAccountId) {
  const row = db
    .prepare(
      `SELECT users.* FROM users
       JOIN oauth_accounts ON oauth_accounts.userId = users.id
       WHERE oauth_accounts.provider = ? AND oauth_accounts.providerAccountId = ?`
    )
    .get(provider, providerAccountId);
  return rowToUser(row);
}
