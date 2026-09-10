/**
 * A tiny in-process fake OAuth2 provider so the test suite can
 * exercise the real /oauth/:provider/callback flow -- real code
 * exchange, real HTTP calls to a token endpoint and a userinfo
 * endpoint -- without real GitHub/Google credentials or the network.
 *
 * Only /oauth/token and /oauth/userinfo are implemented (no
 * /oauth/authorize page): the test suite doesn't need to render a
 * consent screen, only to hand the server a `code` and later see it
 * get exchanged correctly.
 */

import http from "node:http";

export async function startMockOAuthProvider() {
  const profilesByCode = new Map();

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");

    if (req.method === "POST" && url.pathname === "/oauth/token") {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const params = new URLSearchParams(Buffer.concat(chunks).toString("utf-8"));
      const code = params.get("code");

      if (!profilesByCode.has(code)) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_grant" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: `access-token-for-${code}`, token_type: "bearer" }));
      return;
    }

    if (req.method === "GET" && url.pathname === "/oauth/userinfo") {
      const header = req.headers.authorization || "";
      const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : null;
      const code = token?.replace("access-token-for-", "");
      const profile = code ? profilesByCode.get(code) : null;

      if (!profile) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_token" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(profile));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => server.listen(0, resolve));
  const baseUrl = `http://localhost:${server.address().port}`;

  return {
    server,
    baseUrl,
    /** Registers that exchanging `code` should yield `profile`. */
    setProfileForCode(code, profile) {
      profilesByCode.set(code, profile);
    },
    providerConfig() {
      return {
        clientId: "mock-client-id",
        clientSecret: "mock-client-secret",
        redirectUri: `${baseUrl}/callback`,
        authorizationUrl: `${baseUrl}/oauth/authorize`,
        tokenUrl: `${baseUrl}/oauth/token`,
        userInfoUrl: `${baseUrl}/oauth/userinfo`,
        scope: "profile email",
        mapProfile: (profile) => ({ providerAccountId: String(profile.id), email: profile.email }),
      };
    },
  };
}
