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
  findRefreshToken,
  findUserByEmail,
  findUserById,
  insertRefreshToken,
  openDb,
  revokeAllRefreshTokensForUser,
  revokeRefreshToken,
} from "./db.js";
import { hashPassword, verifyPassword } from "./lib/passwords.js";
import { expiresAt, generateToken, hashToken, isExpired } from "./lib/tokens.js";
import { normalizeEmail, validateEmail, validatePassword } from "./lib/validation.js";
import { signJwt, verifyJwt } from "./lib/jwt.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "public");

const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
const DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

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
  const tokens = issueTokenPair(db, user, config);
  return { user: publicUser(user), ...tokens };
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

// ---- router ----

async function handleApiRequest(db, config, req, res, segments) {
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
  };
  if (typeof config.jwtSecret !== "string" || config.jwtSecret.length === 0) {
    throw new Error("createServer requires a non-empty jwtSecret.");
  }

  const db = openDb(options.dbPath);

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    const segments = url.pathname.split("/").filter(Boolean);

    if (segments[0] === "api") {
      handleApiRequest(db, config, req, res, segments).catch((err) => {
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
  });
  const port = process.env.PORT || 3000;
  server.listen(port, () => {
    console.log(`Auth service listening on http://localhost:${port}`);
  });
}
