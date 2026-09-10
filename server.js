/**
 * The reference REST API wiring lib/ + db.js together. This file
 * (and only this file) is the "reusable brick" turned into an actual
 * running service -- lib/ and db.js are the parts meant to be lifted
 * into another project as-is; this is what using them looks like.
 *
 * Tokens: a short-lived JWT access token (stateless, verified with no
 * database lookup) plus a long-lived, single-use, revocable refresh
 * token (a random value from lib/tokens.js, stored only as a hash).
 * Every /refresh call rotates the refresh token -- the old one is
 * revoked and a new one issued -- and presenting an already-revoked
 * refresh token revokes *every* refresh token that user has, on the
 * theory that a revoked token being replayed means someone (not
 * necessarily the legitimate user) has a copy of an old token, which
 * is exactly what rotation is meant to catch.
 */

import { readFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

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
} from "./db.js";
import { PROVIDERS, buildAuthorizationUrl, getOAuthIdentity, resolveProvider } from "./lib/oauth.js";
import { hashPassword, verifyPassword } from "./lib/passwords.js";
import { expiresAt, generateToken, hashToken, isExpired } from "./lib/tokens.js";
import { normalizeEmail, validateEmail, validatePassword } from "./lib/validation.js";
import { signJwt, verifyJwt } from "./lib/jwt.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "public");

const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
const DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const DEFAULT_PASSWORD_RESET_TTL_SECONDS = 60 * 60; // 1 hour
const DEFAULT_EMAIL_VERIFICATION_TTL_SECONDS = 24 * 60 * 60; // 24 hours

/** Sending real email is a deployment concern, not this brick's --
 * these default stubs just log the link a real implementation would
 * email. A caller wires up a real mailer (SES, SendGrid, nodemailer,
 * ...) by passing sendPasswordResetEmail/sendVerificationEmail to
 * createServer(); tests pass a spy to capture the token without
 * needing either a real mailer or a backdoor in the HTTP response
 * (the reset/verification token is a credential -- it must never
 * travel back over the same channel that requested it). */
function defaultSendPasswordResetEmail(user, rawToken) {
  console.log(`[dev] Password reset link for ${user.email}: /?token=${rawToken}#reset-password`);
}
function defaultSendVerificationEmail(user, rawToken) {
  console.log(`[dev] Email verification link for ${user.email}: /?token=${rawToken}#verify-email`);
}

// A fixed, validly-formatted (but useless) hash to run login's
// password check against when the email isn't registered, so
// "unknown email" and "wrong password" take about the same amount of
// time -- otherwise a fast rejection on an unknown email is itself a
// way to enumerate which addresses have an account.
const DUMMY_PASSWORD_HASH = await hashPassword("not-a-real-password-used-only-for-timing-1");

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf-8"));
  } catch {
    throw new HttpError(400, "Invalid JSON body.");
  }
}

function publicUser(user) {
  return { id: user.id, email: user.email, emailVerified: user.emailVerified, createdAt: user.createdAt };
}

function issueTokenPair(db, user, config) {
  const accessToken = signJwt({ sub: user.id }, config.jwtSecret, {
    expiresInSeconds: config.accessTokenTtlSeconds,
  });
  const refreshToken = generateToken();
  insertRefreshToken(db, {
    userId: user.id,
    tokenHash: hashToken(refreshToken),
    expiresAt: expiresAt(config.refreshTokenTtlSeconds),
  });
  return { accessToken, refreshToken };
}

function getBearerToken(req) {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) return null;
  return header.slice("Bearer ".length).trim();
}

/** Throws HttpError(401, ...) rather than returning null/undefined --
 * every caller wants "reject the request" on failure, so there's no
 * case where forgetting to check a falsy return value would silently
 * treat an unauthenticated request as authenticated. */
function requireUser(req, db, config) {
  const token = getBearerToken(req);
  if (!token) throw new HttpError(401, "Missing bearer token.");
  const payload = verifyJwt(token, config.jwtSecret);
  if (!payload || !payload.sub) throw new HttpError(401, "Invalid or expired access token.");
  const user = findUserById(db, payload.sub);
  if (!user) throw new HttpError(401, "Invalid or expired access token.");
  return user;
}

// ---- route handlers ----

async function handleRegister(db, config, body) {
  const emailCheck = validateEmail(body.email);
  if (!emailCheck.valid) throw new HttpError(400, emailCheck.reason);
  const passwordCheck = validatePassword(body.password);
  if (!passwordCheck.valid) throw new HttpError(400, passwordCheck.reason);

  const email = normalizeEmail(body.email);
  if (findUserByEmail(db, email)) throw new HttpError(409, "An account with this email already exists.");

  const passwordHash = await hashPassword(body.password);
  const user = createUser(db, { email, passwordHash });
  sendVerificationEmail(db, config, user);
  const tokens = issueTokenPair(db, user, config);
  return { user: publicUser(user), ...tokens };
}

function sendVerificationEmail(db, config, user) {
  invalidateEmailVerificationTokensForUser(db, user.id);
  const rawToken = generateToken();
  insertEmailVerificationToken(db, {
    userId: user.id,
    tokenHash: hashToken(rawToken),
    expiresAt: expiresAt(config.emailVerificationTtlSeconds),
  });
  config.sendVerificationEmail(user, rawToken);
}

async function handleLogin(db, config, body) {
  if (typeof body.email !== "string" || typeof body.password !== "string") {
    throw new HttpError(400, "Email and password are required.");
  }

  const user = findUserByEmail(db, normalizeEmail(body.email));
  const passwordOk = await verifyPassword(body.password, user ? user.passwordHash : DUMMY_PASSWORD_HASH);

  if (!user || !user.passwordHash || !passwordOk) {
    throw new HttpError(401, "Invalid email or password.");
  }

  const tokens = issueTokenPair(db, user, config);
  return { user: publicUser(user), ...tokens };
}

function handleRefresh(db, config, body) {
  if (typeof body.refreshToken !== "string" || !body.refreshToken) {
    throw new HttpError(400, "refreshToken is required.");
  }

  const tokenHash = hashToken(body.refreshToken);
  const stored = findRefreshToken(db, tokenHash);
  if (!stored) throw new HttpError(401, "Invalid refresh token.");

  if (stored.revoked) {
    // A revoked token being presented again means a copy of it is
    // circulating somewhere it shouldn't be -- lock the account's
    // other sessions out too, not just this one.
    revokeAllRefreshTokensForUser(db, stored.userId);
    throw new HttpError(401, "Invalid refresh token.");
  }
  if (isExpired(stored.expiresAt)) throw new HttpError(401, "Refresh token expired.");

  const user = findUserById(db, stored.userId);
  if (!user) throw new HttpError(401, "Invalid refresh token.");

  revokeRefreshToken(db, tokenHash);
  return { user: publicUser(user), ...issueTokenPair(db, user, config) };
}

function handleLogout(db, body) {
  if (typeof body.refreshToken !== "string" || !body.refreshToken) {
    throw new HttpError(400, "refreshToken is required.");
  }
  revokeRefreshToken(db, hashToken(body.refreshToken));
  // Always 204, even if the token was already invalid/unknown --
  // logging out is idempotent from the caller's point of view.
}

const GENERIC_FORGOT_PASSWORD_MESSAGE = "If that email is registered, a password reset link has been sent.";

function handleForgotPassword(db, config, body) {
  const emailCheck = validateEmail(body.email);
  if (!emailCheck.valid) throw new HttpError(400, emailCheck.reason);

  // Same response whether or not the account exists -- confirming a
  // negative here is exactly the enumeration a generic message on
  // /login is also trying to prevent.
  const user = findUserByEmail(db, normalizeEmail(body.email));
  if (user) {
    invalidatePasswordResetTokensForUser(db, user.id);
    const rawToken = generateToken();
    insertPasswordResetToken(db, {
      userId: user.id,
      tokenHash: hashToken(rawToken),
      expiresAt: expiresAt(config.passwordResetTtlSeconds),
    });
    config.sendPasswordResetEmail(user, rawToken);
  }
  return { message: GENERIC_FORGOT_PASSWORD_MESSAGE };
}

async function handleResetPassword(db, body) {
  if (typeof body.token !== "string" || !body.token) throw new HttpError(400, "token is required.");
  const passwordCheck = validatePassword(body.newPassword);
  if (!passwordCheck.valid) throw new HttpError(400, passwordCheck.reason);

  const stored = findPasswordResetToken(db, hashToken(body.token));
  // One generic error for not-found, already-used and expired alike --
  // distinguishing them tells an attacker holding a guessed/stale
  // token more than they should learn from a single response.
  if (!stored || stored.used || isExpired(stored.expiresAt)) {
    throw new HttpError(400, "This reset link is invalid or has expired.");
  }

  const passwordHash = await hashPassword(body.newPassword);
  updatePasswordHash(db, stored.userId, passwordHash);
  markPasswordResetTokenUsed(db, hashToken(body.token));
  // A password reset is a "this session may have been compromised"
  // event -- force every device to log in again with the new password.
  revokeAllRefreshTokensForUser(db, stored.userId);

  return { message: "Password has been reset. Please log in again." };
}

const GENERIC_RESEND_VERIFICATION_MESSAGE = "If that email is registered and unverified, a verification link has been sent.";

function handleResendVerification(db, config, body) {
  const emailCheck = validateEmail(body.email);
  if (!emailCheck.valid) throw new HttpError(400, emailCheck.reason);

  const user = findUserByEmail(db, normalizeEmail(body.email));
  if (user && !user.emailVerified) {
    sendVerificationEmail(db, config, user);
  }
  return { message: GENERIC_RESEND_VERIFICATION_MESSAGE };
}

function handleVerifyEmail(db, body) {
  if (typeof body.token !== "string" || !body.token) throw new HttpError(400, "token is required.");

  const stored = findEmailVerificationToken(db, hashToken(body.token));
  if (!stored || stored.used || isExpired(stored.expiresAt)) {
    throw new HttpError(400, "This verification link is invalid or has expired.");
  }

  setEmailVerified(db, stored.userId);
  markEmailVerificationTokenUsed(db, hashToken(body.token));
  return { message: "Email verified." };
}

/** Looks up a provider by name in config.oauthProviders (credentials
 * only) and merges it with lib/oauth.js's preset when there is one.
 * A name with no preset (e.g. "mock", used by the test suite and the
 * self-hosted-provider demo in the README) must supply its own
 * endpoints + mapProfile since there's no preset to merge with. */
function resolveConfiguredProvider(config, name) {
  const credentials = config.oauthProviders?.[name];
  if (!credentials) return null;
  if (PROVIDERS[name]) return resolveProvider(name, credentials);
  if (!credentials.authorizationUrl || !credentials.tokenUrl || !credentials.userInfoUrl || !credentials.mapProfile) {
    throw new Error(`OAuth provider "${name}" has no preset and is missing required endpoint config.`);
  }
  return credentials;
}

/** A short-lived, stateless anti-CSRF state parameter: rather than
 * keeping a server-side table of "states we issued" (which wouldn't
 * survive a restart and wouldn't work behind a load balancer without
 * shared storage), the state itself is a signed, expiring token --
 * verifying it needs nothing but the JWT secret this process already
 * has. */
function createOAuthState(config) {
  return signJwt({ purpose: "oauth-state" }, config.jwtSecret, { expiresInSeconds: 600 });
}

function isValidOAuthState(config, state) {
  if (typeof state !== "string") return false;
  const payload = verifyJwt(state, config.jwtSecret);
  return Boolean(payload && payload.purpose === "oauth-state");
}

function handleOAuthAuthorize(config, res, providerName) {
  const provider = resolveConfiguredProvider(config, providerName);
  if (!provider) throw new HttpError(404, `OAuth provider "${providerName}" is not configured.`);
  const state = createOAuthState(config);
  res.writeHead(302, { Location: buildAuthorizationUrl(provider, { state }) });
  res.end();
}

async function handleOAuthCallback(db, config, res, providerName, searchParams) {
  const provider = resolveConfiguredProvider(config, providerName);
  if (!provider) throw new HttpError(404, `OAuth provider "${providerName}" is not configured.`);
  if (!isValidOAuthState(config, searchParams.get("state"))) {
    throw new HttpError(400, "Invalid or expired OAuth state.");
  }
  const code = searchParams.get("code");
  if (!code) throw new HttpError(400, "Missing authorization code.");

  const identity = await getOAuthIdentity(provider, code);

  let user = findUserByOAuthAccount(db, providerName, identity.providerAccountId);
  if (!user) {
    // The provider has already verified this email on their end, and
    // an existing local account with the same address is treated as
    // the same person -- sign in with Google using the address you
    // already registered with a password links the two rather than
    // creating a second, disconnected account.
    user = identity.email ? findUserByEmail(db, normalizeEmail(identity.email)) : null;
    if (!user) {
      user = createUser(db, { email: normalizeEmail(identity.email), passwordHash: null });
    }
    if (!user.emailVerified) setEmailVerified(db, user.id);
    linkOAuthAccount(db, { userId: user.id, provider: providerName, providerAccountId: identity.providerAccountId });
  }

  const tokens = issueTokenPair(db, user, config);
  // Tokens travel in the URL fragment, not the query string: a
  // fragment is never sent to the server (by this redirect or a
  // subsequent one) and never forwarded in a Referer header, unlike a
  // query parameter would be. The page at oauthSuccessRedirect reads
  // it client-side (see public/oauth-callback.html).
  const fragment = new URLSearchParams({ access_token: tokens.accessToken, refresh_token: tokens.refreshToken });
  res.writeHead(302, { Location: `${config.oauthSuccessRedirect}#${fragment.toString()}` });
  res.end();
}

// ---- router ----

async function handleApiRequest(db, config, req, res, segments, url) {
  if (segments[1] === "auth" && segments[2] === "register" && segments.length === 3 && req.method === "POST") {
    const body = await readJsonBody(req);
    return sendJson(res, 201, await handleRegister(db, config, body));
  }

  if (segments[1] === "auth" && segments[2] === "login" && segments.length === 3 && req.method === "POST") {
    const body = await readJsonBody(req);
    return sendJson(res, 200, await handleLogin(db, config, body));
  }

  if (segments[1] === "auth" && segments[2] === "refresh" && segments.length === 3 && req.method === "POST") {
    const body = await readJsonBody(req);
    return sendJson(res, 200, handleRefresh(db, config, body));
  }

  if (segments[1] === "auth" && segments[2] === "logout" && segments.length === 3 && req.method === "POST") {
    const body = await readJsonBody(req);
    handleLogout(db, body);
    res.writeHead(204);
    return res.end();
  }

  if (
    segments[1] === "auth" &&
    segments[2] === "forgot-password" &&
    segments.length === 3 &&
    req.method === "POST"
  ) {
    const body = await readJsonBody(req);
    return sendJson(res, 200, handleForgotPassword(db, config, body));
  }

  if (
    segments[1] === "auth" &&
    segments[2] === "reset-password" &&
    segments.length === 3 &&
    req.method === "POST"
  ) {
    const body = await readJsonBody(req);
    return sendJson(res, 200, await handleResetPassword(db, body));
  }

  if (
    segments[1] === "auth" &&
    segments[2] === "resend-verification" &&
    segments.length === 3 &&
    req.method === "POST"
  ) {
    const body = await readJsonBody(req);
    return sendJson(res, 200, handleResendVerification(db, config, body));
  }

  if (segments[1] === "auth" && segments[2] === "verify-email" && segments.length === 3 && req.method === "POST") {
    const body = await readJsonBody(req);
    return sendJson(res, 200, handleVerifyEmail(db, body));
  }

  if (segments[1] === "auth" && segments[2] === "oauth" && segments.length === 4 && req.method === "GET") {
    return handleOAuthAuthorize(config, res, segments[3]);
  }

  if (
    segments[1] === "auth" &&
    segments[2] === "oauth" &&
    segments[4] === "callback" &&
    segments.length === 5 &&
    req.method === "GET"
  ) {
    return handleOAuthCallback(db, config, res, segments[3], url.searchParams);
  }

  if (segments[1] === "me" && segments.length === 2 && req.method === "GET") {
    const user = requireUser(req, db, config);
    return sendJson(res, 200, { user: publicUser(user) });
  }

  throw new HttpError(404, "Not found.");
}

async function serveStatic(res, pathname) {
  const relative = pathname === "/" ? "index.html" : pathname.slice(1);
  const filePath = path.normalize(path.join(PUBLIC_DIR, relative));

  if (!filePath.startsWith(PUBLIC_DIR)) {
    return sendJson(res, 403, { error: "Forbidden." });
  }

  const CONTENT_TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8" };
  try {
    const data = await readFile(filePath);
    res.writeHead(200, { "Content-Type": CONTENT_TYPES[path.extname(filePath)] || "application/octet-stream" });
    res.end(data);
  } catch {
    sendJson(res, 404, { error: "Not found." });
  }
}

export function createServer(options) {
  const config = {
    jwtSecret: options.jwtSecret,
    accessTokenTtlSeconds: options.accessTokenTtlSeconds ?? DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTtlSeconds: options.refreshTokenTtlSeconds ?? DEFAULT_REFRESH_TOKEN_TTL_SECONDS,
    passwordResetTtlSeconds: options.passwordResetTtlSeconds ?? DEFAULT_PASSWORD_RESET_TTL_SECONDS,
    emailVerificationTtlSeconds: options.emailVerificationTtlSeconds ?? DEFAULT_EMAIL_VERIFICATION_TTL_SECONDS,
    sendPasswordResetEmail: options.sendPasswordResetEmail ?? defaultSendPasswordResetEmail,
    sendVerificationEmail: options.sendVerificationEmail ?? defaultSendVerificationEmail,
    oauthProviders: options.oauthProviders ?? {},
    oauthSuccessRedirect: options.oauthSuccessRedirect ?? "/oauth-callback.html",
  };
  if (typeof config.jwtSecret !== "string" || config.jwtSecret.length === 0) {
    throw new Error("createServer requires a non-empty jwtSecret.");
  }

  const db = openDb(options.dbPath);

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    const segments = url.pathname.split("/").filter(Boolean);

    if (segments[0] === "api") {
      handleApiRequest(db, config, req, res, segments, url).catch((err) => {
        if (err instanceof HttpError) sendJson(res, err.status, { error: err.message });
        else sendJson(res, 500, { error: "Internal server error." });
      });
      return;
    }

    if (req.method === "GET") {
      serveStatic(res, url.pathname).catch(() => sendJson(res, 500, { error: "Internal server error." }));
      return;
    }

    sendJson(res, 404, { error: "Not found." });
  });

  server.db = db;
  return server;
}

/** Reads FOO_CLIENT_ID/FOO_CLIENT_SECRET/FOO_REDIRECT_URI for each
 * known preset out of env vars, and includes a provider only when all
 * three are set -- an unconfigured provider's /oauth/:name route
 * 404s rather than the server refusing to start over it. */
function oauthProvidersFromEnv(env) {
  const providers = {};
  for (const name of Object.keys(PROVIDERS)) {
    const prefix = name.toUpperCase();
    const clientId = env[`${prefix}_CLIENT_ID`];
    const clientSecret = env[`${prefix}_CLIENT_SECRET`];
    const redirectUri = env[`${prefix}_REDIRECT_URI`];
    if (clientId && clientSecret && redirectUri) {
      providers[name] = { clientId, clientSecret, redirectUri };
    }
  }
  return providers;
}

const isMainModule = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable is required (see .env.example).");
  }
  const server = createServer({
    dbPath: process.env.DB_PATH || "auth.sqlite",
    jwtSecret: process.env.JWT_SECRET,
    accessTokenTtlSeconds: process.env.ACCESS_TOKEN_TTL_SECONDS
      ? Number(process.env.ACCESS_TOKEN_TTL_SECONDS)
      : undefined,
    refreshTokenTtlSeconds: process.env.REFRESH_TOKEN_TTL_SECONDS
      ? Number(process.env.REFRESH_TOKEN_TTL_SECONDS)
      : undefined,
    oauthProviders: oauthProvidersFromEnv(process.env),
  });
  const port = process.env.PORT || 3000;
  server.listen(port, () => {
    console.log(`Auth service listening on http://localhost:${port}`);
  });
}
