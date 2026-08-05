# @exortek/oauth2

## 1.0.0

### Major Changes

- b33deb0: Initial release. OAuth 2.1 for Node.js 22+ — the relying-party flow and a full authorization server, secure
  by default.

  - `createOAuth` — the relying-party flow (PKCE S256, `state` / `nonce` generated and verified, exact `redirect_uri` +
    RFC 9207 `iss` matching) with 18 provider presets (`./providers/*`: google, github, microsoft, azure, discord,
    facebook, linkedin, spotify, twitch, apple, twitter, okta, gitlab, bitbucket, slack, reddit, amazon, salesforce).
  - Login middleware for Express (`./express`) and Fastify (`./fastify`) — `web` (browser redirect, HMAC-signed or
    JWE-sealed flow-session cookie / store) and `api` (client-held session for mobile / SPA / CLI) modes; every platform
    from the backend.
  - `createServer` — an OAuth 2.1 authorization server (`./server` + `./server/express` / `./server/fastify` adapters):
    authorize / token / revoke / introspect / PAR / device / registration endpoints, RFC 8414 metadata, `jwtIssuer` (RFC
    9068 `at+jwt`, default) + pluggable `pasetoIssuer`.
  - OpenID Connect — an optional `oidc` config turns the server into an OpenID Provider: it issues a signed `id_token`
    (with `nonce`, `auth_time`, and `at_hash`) whenever a request is granted the `openid` scope, and serves an OIDC
    discovery document. Without it the server stays a plain OAuth 2.1 AS and does not advertise `openid-configuration`.
  - Dynamic Client Registration (RFC 7591) — an opt-in `/register` endpoint, initial-access-token gated by default (open
    registration is explicit), that mints and persists a client through the registry.
  - Modern hardening — DPoP (RFC 9449, incl. the nonce challenge), PKCE (RFC 7636), PAR (RFC 9126), resource indicators
    (RFC 8707), RAR (RFC 9396), JAR/JARM (RFC 9101, request objects require `exp` and are single-use), `private_key_jwt`
    / `client_secret_jwt` (RFC 7523), mTLS (RFC 8705), token exchange (RFC 8693), device grant (RFC 8628,
    client-authenticated), and the FAPI 2.0 profile. `verifyDpopForResource` for the resource-server half.
  - In-memory and Redis-backed authorization-server stores behind one contract.
  - Zero non-`@exortek/*` runtime dependencies.
