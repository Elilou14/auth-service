# Auth Service

A reusable authentication brick -- registration, login, JWT access + refresh
tokens, password reset, email verification, OAuth2 -- meant to be dropped
into other projects, not just run standalone. Zero runtime dependencies:
`node:crypto`, `node:sqlite`, `node:http`, nothing from npm.

[![CI](https://github.com/Elilou14/auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/Elilou14/auth-service/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![Profile page screenshot](docs/screenshot.png)

## Why this exists

Every project in this portfolio eventually needs the same thing: users who
can sign up, log in, reset a forgotten password, and (increasingly) sign in
with GitHub or Google. This project builds that once, tested thoroughly,
so it can be copied wholesale into the next one instead of rewritten -- see
[Reusing this in another project](#reusing-this-in-another-project).

## Architecture

```
lib/            <- the reusable core: pure functions, no I/O
  passwords.js    scrypt hashing (no bcrypt/argon2 dependency needed)
  jwt.js          HS256 sign/verify, hand-rolled on purpose (see below)
  tokens.js       single-use tokens for email verification / password reset
  oauth.js        a generic OAuth2 Authorization Code client
db.js           <- SQLite persistence (node:sqlite): users, refresh
                   tokens, reset/verification tokens, OAuth account links
server.js       <- the reference REST API wiring lib/ + db.js together
public/         <- a minimal demo frontend exercising every endpoint
tests/          <- 176 tests (node:test) covering all of the above
```

`lib/` and `db.js` know nothing about HTTP -- every function takes plain
values in and returns plain values (or throws) out. `server.js` is what
*using* them looks like: request parsing, routing, and turning a thrown
error into the right HTTP status. That split is what makes `lib/` + `db.js`
liftable into a different transport (a GraphQL resolver, a CLI, a different
router) without rewriting the actual rules.

## Security decisions (and why)

- **Passwords are hashed with scrypt** (`node:crypto`, built in) rather than
  a bcrypt/argon2 dependency -- scrypt is memory-hard and OWASP's own
  recommendation when argon2 isn't available. The cost parameters travel
  with the hash (`scrypt$N$r$p$salt$hash`), so a future cost bump doesn't
  break verifying old hashes.
- **JWTs are hand-rolled and HS256-only.** `verifyJwt` hardcodes the
  algorithm and ignores whatever `alg` a token's header claims -- that's
  what closes off the classic "alg: none" / alg-confusion attacks, which
  exist precisely because most JWT libraries trust the token to say what
  algorithm to verify it with.
- **Two token types, different lifetimes and different trust models.** A
  short-lived (15 min default) JWT access token is stateless -- no database
  lookup to verify it, cheap for every request, but impossible to revoke
  before it expires. A long-lived (30 day default) refresh token is a
  random value, stored only as a hash, single-use, and revocable: every
  `/refresh` rotates it (the old one is revoked, a new one issued), and
  *replaying an already-revoked refresh token revokes every refresh token
  that user has* -- that reuse is a signal a copy of an old token exists
  somewhere it shouldn't, which is exactly what rotation exists to catch.
- **Generic error messages, and timing that doesn't undermine them.**
  Login returns the same "Invalid email or password." whether the email
  doesn't exist or the password is wrong, and runs the password check
  against a fixed dummy hash when the email isn't registered -- otherwise a
  fast rejection on an unknown email is itself a way to enumerate which
  addresses have an account. `/forgot-password` and `/resend-verification`
  always return the same 200 regardless of whether the address is
  registered, for the same reason; `/reset-password` and `/verify-email`
  return one generic 400 for not-found, already-used, and expired tokens
  alike.
- **Reset/verification tokens are single-use, hashed at rest, and
  superseded on reissue.** The raw token is what would get emailed and is
  never persisted -- only its SHA-256 hash is stored, so a database leak
  doesn't hand out usable tokens. Requesting a new one invalidates whatever
  was issued before it. A successful password reset also revokes every
  refresh token for that user, on the same "this session may be
  compromised" reasoning as the refresh-reuse handling above.
- **The reset/verification token never travels back through the HTTP
  response that requested it.** Sending real email is a deployment
  concern -- `server.js` abstracts it behind
  `sendPasswordResetEmail`/`sendVerificationEmail` (default: log the link;
  a real deployment injects SES/SendGrid/nodemailer/etc. through the same
  seam). Returning the token in the API response instead would just
  relocate the vulnerability a "click the link we emailed you" flow exists
  to avoid.
- **OAuth state is a signed, expiring token, not server-side session
  storage.** `/oauth/:provider` signs a short-lived JWT as the anti-CSRF
  `state` parameter; the callback verifies it with the same secret. No
  shared state store needed, which means it works unmodified behind
  multiple server instances.
- **OAuth tokens come back in the redirect's URL fragment, not the query
  string.** A fragment is never sent to any server (by that redirect or a
  later one) and never forwarded in a `Referer` header; a query parameter
  would be both. `public/oauth-callback.html`'s only job is moving them out
  of the URL and into storage.
- **Signing in with a provider links to an existing account by verified
  email**, rather than always creating a new one -- the provider has
  already verified that address, so it's treated as the same person, not a
  duplicate identity.

## API reference

| Method & path | Auth | Body | Notes |
|---|---|---|---|
| `POST /api/auth/register` | -- | `email`, `password` | 201, returns `user` + `accessToken` + `refreshToken`. Also queues a verification email. |
| `POST /api/auth/login` | -- | `email`, `password` | 200, same shape as register. |
| `POST /api/auth/refresh` | -- | `refreshToken` | 200, rotates the refresh token. |
| `POST /api/auth/logout` | -- | `refreshToken` | 204, idempotent. |
| `GET /api/me` | Bearer access token | -- | 200, the authenticated user. |
| `POST /api/auth/forgot-password` | -- | `email` | 200 always (generic message). |
| `POST /api/auth/reset-password` | -- | `token`, `newPassword` | 200; revokes all refresh tokens for that user. |
| `POST /api/auth/resend-verification` | -- | `email` | 200 always (generic message). |
| `POST /api/auth/verify-email` | -- | `token` | 200. |
| `GET /api/auth/oauth/:provider` | -- | -- | 302 to the provider's consent screen. |
| `GET /api/auth/oauth/:provider/callback` | -- | -- (`code`, `state` query params) | 302 to `oauthSuccessRedirect` with tokens in the URL fragment. |

## Setup

```bash
cp .env.example .env
# fill in JWT_SECRET at minimum:
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
npm start
# -> http://localhost:3000
```

OAuth is optional: a provider (`github`, `google`) only turns on once its
`_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URI` trio is set in `.env`; an
unconfigured provider's `/oauth/:name` route just 404s rather than the
server refusing to start.

## Reusing this in another project

Copy `lib/` and `db.js` into the new project as-is -- nothing in them
imports from `server.js` or `public/`. Then either copy `server.js` as a
starting point for that project's own routes, or call the same functions
(`hashPassword`, `signJwt`/`verifyJwt`, `createUser`, `issueTokenPair`'s
logic, ...) directly from whatever router that project already has.
Everything configurable (token TTLs, the mailer functions, OAuth provider
credentials) is a plain argument to `createServer()` / the `lib/` functions
themselves -- nothing reaches into `process.env` below `server.js`'s own
entrypoint, which is what keeps the rest testable and reusable without a
particular deployment's environment.

## Running the tests

```bash
node --test
```

176 tests: every `lib/` function's happy path and edge cases, the full
SQLite layer, and the REST API end-to-end via real `fetch()` calls against
an ephemeral server -- including a from-scratch in-process mock OAuth2
provider (`tests/helpers/mock-oauth-provider.js`) that exercises the real
authorize -> callback -> code exchange -> profile fetch -> account
creation/linking chain without real GitHub/Google credentials.

## CI

`.github/workflows/ci.yml` runs the full suite above on every push and pull
request to `main`.

## License

MIT -- see [LICENSE](LICENSE).
