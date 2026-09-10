import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createUser,
  findEmailVerificationToken,
  findPasswordResetToken,
  findRefreshToken,
  findUserByEmail,
  findUserById,
  findUserByOAuthAccount,
  insertEmailVerificationToken,
  insertPasswordResetToken,
  insertRefreshToken,
  invalidateEmailVerificationTokensForUser,
  invalidatePasswordResetTokensForUser,
  linkOAuthAccount,
  markEmailVerificationTokenUsed,
  markPasswordResetTokenUsed,
  openDb,
  revokeAllRefreshTokensForUser,
  revokeRefreshToken,
  setEmailVerified,
  updatePasswordHash,
} from "../db.js";

let nextId = 0;
function testId() {
  nextId += 1;
  return `id-${nextId}`;
}

function userDb() {
  const db = openDb(":memory:");
  const user = createUser(db, { email: "alice@example.com", passwordHash: "scrypt$..." }, testId);
  return { db, user };
}

test("createUser / findUserByEmail / findUserById", async (t) => {
  await t.test("creates a user with emailVerified false and the given fields", () => {
    const db = openDb(":memory:");
    const user = createUser(db, { email: "alice@example.com", passwordHash: "hash1" }, testId);
    assert.equal(user.email, "alice@example.com");
    assert.equal(user.passwordHash, "hash1");
    assert.equal(user.emailVerified, false);
  });

  await t.test("allows a null passwordHash (OAuth-only account)", () => {
    const db = openDb(":memory:");
    const user = createUser(db, { email: "oauth@example.com" }, testId);
    assert.equal(user.passwordHash, null);
  });

  await t.test("rejects a duplicate email", () => {
    const db = openDb(":memory:");
    createUser(db, { email: "alice@example.com", passwordHash: "h" }, testId);
    assert.throws(() => createUser(db, { email: "alice@example.com", passwordHash: "h2" }, testId));
  });

  await t.test("findUserByEmail / findUserById round-trip, null when not found", () => {
    const { db, user } = userDb();
    assert.deepEqual(findUserByEmail(db, "alice@example.com"), user);
    assert.deepEqual(findUserById(db, user.id), user);
    assert.equal(findUserByEmail(db, "missing@example.com"), null);
    assert.equal(findUserById(db, "missing"), null);
  });
});

test("setEmailVerified / updatePasswordHash", async (t) => {
  await t.test("setEmailVerified flips the flag", () => {
    const { db, user } = userDb();
    assert.equal(setEmailVerified(db, user.id), true);
    assert.equal(findUserById(db, user.id).emailVerified, true);
  });

  await t.test("setEmailVerified on an unknown id returns false", () => {
    const { db } = userDb();
    assert.equal(setEmailVerified(db, "missing"), false);
  });

  await t.test("updatePasswordHash replaces the hash", () => {
    const { db, user } = userDb();
    assert.equal(updatePasswordHash(db, user.id, "new-hash"), true);
    assert.equal(findUserById(db, user.id).passwordHash, "new-hash");
  });
});

test("refresh tokens", async (t) => {
  await t.test("insert then find round-trips, unrevoked by default", () => {
    const { db, user } = userDb();
    insertRefreshToken(db, { userId: user.id, tokenHash: "hash-a", expiresAt: Date.now() + 1000 }, testId);
    const found = findRefreshToken(db, "hash-a");
    assert.equal(found.userId, user.id);
    assert.equal(found.revoked, false);
  });

  await t.test("find returns null for an unknown hash", () => {
    const { db } = userDb();
    assert.equal(findRefreshToken(db, "missing"), null);
  });

  await t.test("revokeRefreshToken flips revoked and reports whether it found one", () => {
    const { db, user } = userDb();
    insertRefreshToken(db, { userId: user.id, tokenHash: "hash-a", expiresAt: Date.now() + 1000 }, testId);
    assert.equal(revokeRefreshToken(db, "hash-a"), true);
    assert.equal(findRefreshToken(db, "hash-a").revoked, true);
    assert.equal(revokeRefreshToken(db, "missing"), false);
  });

  await t.test("revokeAllRefreshTokensForUser revokes only that user's unrevoked tokens", () => {
    const { db, user } = userDb();
    const otherUser = createUser(db, { email: "bob@example.com", passwordHash: "h" }, testId);
    insertRefreshToken(db, { userId: user.id, tokenHash: "a", expiresAt: Date.now() + 1000 }, testId);
    insertRefreshToken(db, { userId: user.id, tokenHash: "b", expiresAt: Date.now() + 1000 }, testId);
    insertRefreshToken(db, { userId: otherUser.id, tokenHash: "c", expiresAt: Date.now() + 1000 }, testId);

    const revokedCount = revokeAllRefreshTokensForUser(db, user.id);
    assert.equal(revokedCount, 2);
    assert.equal(findRefreshToken(db, "a").revoked, true);
    assert.equal(findRefreshToken(db, "b").revoked, true);
    assert.equal(findRefreshToken(db, "c").revoked, false);
  });
});

test("password reset tokens", async (t) => {
  await t.test("insert then find round-trips, unused by default", () => {
    const { db, user } = userDb();
    insertPasswordResetToken(db, { userId: user.id, tokenHash: "reset-a", expiresAt: Date.now() + 1000 }, testId);
    const found = findPasswordResetToken(db, "reset-a");
    assert.equal(found.userId, user.id);
    assert.equal(found.used, false);
  });

  await t.test("markPasswordResetTokenUsed flips used", () => {
    const { db, user } = userDb();
    insertPasswordResetToken(db, { userId: user.id, tokenHash: "reset-a", expiresAt: Date.now() + 1000 }, testId);
    assert.equal(markPasswordResetTokenUsed(db, "reset-a"), true);
    assert.equal(findPasswordResetToken(db, "reset-a").used, true);
  });

  await t.test("invalidatePasswordResetTokensForUser marks only that user's unused tokens", () => {
    const { db, user } = userDb();
    const otherUser = createUser(db, { email: "bob@example.com", passwordHash: "h" }, testId);
    insertPasswordResetToken(db, { userId: user.id, tokenHash: "a", expiresAt: Date.now() + 1000 }, testId);
    insertPasswordResetToken(db, { userId: otherUser.id, tokenHash: "b", expiresAt: Date.now() + 1000 }, testId);

    invalidatePasswordResetTokensForUser(db, user.id);
    assert.equal(findPasswordResetToken(db, "a").used, true);
    assert.equal(findPasswordResetToken(db, "b").used, false);
  });
});

test("email verification tokens", async (t) => {
  await t.test("insert then find round-trips, unused by default", () => {
    const { db, user } = userDb();
    insertEmailVerificationToken(db, { userId: user.id, tokenHash: "verify-a", expiresAt: Date.now() + 1000 }, testId);
    const found = findEmailVerificationToken(db, "verify-a");
    assert.equal(found.userId, user.id);
    assert.equal(found.used, false);
  });

  await t.test("markEmailVerificationTokenUsed flips used", () => {
    const { db, user } = userDb();
    insertEmailVerificationToken(db, { userId: user.id, tokenHash: "verify-a", expiresAt: Date.now() + 1000 }, testId);
    assert.equal(markEmailVerificationTokenUsed(db, "verify-a"), true);
    assert.equal(findEmailVerificationToken(db, "verify-a").used, true);
  });

  await t.test("invalidateEmailVerificationTokensForUser marks only that user's unused tokens", () => {
    const { db, user } = userDb();
    const otherUser = createUser(db, { email: "bob@example.com", passwordHash: "h" }, testId);
    insertEmailVerificationToken(db, { userId: user.id, tokenHash: "a", expiresAt: Date.now() + 1000 }, testId);
    insertEmailVerificationToken(db, { userId: otherUser.id, tokenHash: "b", expiresAt: Date.now() + 1000 }, testId);

    invalidateEmailVerificationTokensForUser(db, user.id);
    assert.equal(findEmailVerificationToken(db, "a").used, true);
    assert.equal(findEmailVerificationToken(db, "b").used, false);
  });
});

test("OAuth accounts", async (t) => {
  await t.test("linkOAuthAccount then findUserByOAuthAccount round-trips", () => {
    const { db, user } = userDb();
    linkOAuthAccount(db, { userId: user.id, provider: "github", providerAccountId: "gh-123" }, testId);
    const found = findUserByOAuthAccount(db, "github", "gh-123");
    assert.deepEqual(found, user);
  });

  await t.test("null when no account is linked", () => {
    const { db } = userDb();
    assert.equal(findUserByOAuthAccount(db, "github", "missing"), null);
  });

  await t.test("the same provider account id under a different provider is a different link", () => {
    const { db, user } = userDb();
    linkOAuthAccount(db, { userId: user.id, provider: "github", providerAccountId: "123" }, testId);
    assert.equal(findUserByOAuthAccount(db, "google", "123"), null);
  });

  await t.test("rejects linking the same provider account twice", () => {
    const { db, user } = userDb();
    linkOAuthAccount(db, { userId: user.id, provider: "github", providerAccountId: "123" }, testId);
    assert.throws(() =>
      linkOAuthAccount(db, { userId: user.id, provider: "github", providerAccountId: "123" }, testId)
    );
  });
});
