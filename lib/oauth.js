/**
 * A generic OAuth2 Authorization Code client -- not tied to any one
 * provider. `PROVIDERS` holds the fixed, public parts of a few well-
 * known providers (their endpoints, scope, and how to read an
 * account id + email out of their particular profile response
 * shape); `resolveProvider` merges that with the caller's own
 * clientId/clientSecret/redirectUri (server.js reads those from env
 * vars -- this module never touches process.env itself, so it stays
 * testable with made-up credentials against a fake or local-mock
 * provider).
 *
 * Every network call takes an injectable `fetchImpl` (defaulting to
 * the global fetch), the same dependency-injection seam this
 * portfolio uses for id generators and RNGs elsewhere -- it's what
 * lets the test suite exercise the full exchange-code-for-token ->
 * fetch-profile chain against a fake without touching the network.
 */

import { generateToken } from "./tokens.js";

export const PROVIDERS = {
  github: {
    authorizationUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userInfoUrl: "https://api.github.com/user",
    scope: "read:user user:email",
    mapProfile: (profile) => ({ providerAccountId: String(profile.id), email: profile.email }),
  },
  google: {
    authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
    scope: "openid email profile",
    mapProfile: (profile) => ({ providerAccountId: profile.sub, email: profile.email }),
  },
};

/** Merges a known preset (`PROVIDERS[name]`) with per-deployment
 * credentials `{clientId, clientSecret, redirectUri}`. `credentials`
 * may also fully override endpoints -- that's how the test suite and
 * the local-mock-provider demo point a "provider" at a local server
 * instead of the real github.com/google.com. */
export function resolveProvider(name, credentials) {
  const preset = PROVIDERS[name];
  if (!preset) throw new Error(`Unknown OAuth provider: ${name}`);
  return { ...preset, ...credentials };
}

export function generateState() {
  return generateToken(16);
}

export function buildAuthorizationUrl(provider, { state }) {
  const url = new URL(provider.authorizationUrl);
  url.searchParams.set("client_id", provider.clientId);
  url.searchParams.set("redirect_uri", provider.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", provider.scope);
  url.searchParams.set("state", state);
  return url.toString();
}

export async function exchangeCodeForToken(provider, code, { fetchImpl = fetch } = {}) {
  const res = await fetchImpl(provider.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      client_id: provider.clientId,
      client_secret: provider.clientSecret,
      code,
      redirect_uri: provider.redirectUri,
      grant_type: "authorization_code",
    }),
  });
  if (!res.ok) throw new Error(`OAuth token exchange failed (HTTP ${res.status}).`);
  const data = await res.json();
  if (!data.access_token) throw new Error("OAuth token exchange response is missing access_token.");
  return data;
}

export async function fetchUserProfile(provider, accessToken, { fetchImpl = fetch } = {}) {
  const res = await fetchImpl(provider.userInfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
  });
  if (!res.ok) throw new Error(`Fetching the OAuth user profile failed (HTTP ${res.status}).`);
  return res.json();
}

/** The full chain: exchange the authorization code, fetch the
 * profile, and map it down to `{providerAccountId, email}` -- the
 * only two fields db.js's OAuth linking actually needs. */
export async function getOAuthIdentity(provider, code, options = {}) {
  const tokenResponse = await exchangeCodeForToken(provider, code, options);
  const profile = await fetchUserProfile(provider, tokenResponse.access_token, options);
  const identity = provider.mapProfile(profile);
  if (!identity.providerAccountId) throw new Error("OAuth profile is missing an account id.");
  return identity;
}
