# @exortek/oauth2

## 1.1.1

### Patch Changes

- 89aea87: Ship self-contained TypeScript declarations. Every package's emitted `.d.ts` referenced `@exortek/shared`
  (e.g. `import { BaseError } from '@exortek/shared/errors'`), but `@exortek/shared` is a private, never-published
  workspace package that is inlined into each bundle at build time. A TypeScript consumer therefore hit
  `Cannot find module '@exortek/shared/…'` (with `skipLibCheck` off) or silently degraded error-class types like
  `ApiKeyError` — losing its constructor signature and `.code` / `.message` — with `skipLibCheck` on.

  The build now runs a declaration-bundling pass (`rollup-plugin-dts`) after `tsc`, flattening each entry's `.d.ts` and
  inlining the `@exortek/shared` types so the shipped declarations are fully self-contained. Runtime deps and `node:*`
  stay external. No runtime or API change — types only.

- Updated dependencies [89aea87]
- Updated dependencies [89aea87]
  - @exortek/jwe@1.0.2
  - @exortek/jwk@1.0.4
  - @exortek/jwks@1.1.1
  - @exortek/jws@1.0.4
  - @exortek/jwt@1.3.0
  - @exortek/paseto@1.1.0

## 1.1.0

### Minor Changes

- b4dab8a: Let a deployment constrain which hosts the authorization server will fetch a client's `jwks_uri` from.

  A client's `jwks_uri` is client-supplied, and the server fetches it when verifying `private_key_jwt` client assertions
  and JAR request objects. Under dynamic client registration the value is chosen by whoever registered, so the
  destination is worth constraining.

  `createServer` accepts `security.allowJwksHost`, a predicate receiving the hostname and parsed URL; returning `false`
  refuses the URI. `createRemoteJWKS` gains the same hook as `allowHost`. Both are optional and unset by default —
  existing behaviour is unchanged.

  Recommended wherever `registration` is enabled.

### Patch Changes

- 4162651: Document server storage, and correct the modules table.

  The README never mentioned storage, so a reader following it deployed an authorization server on in-memory stores and
  discovered the problem on the second instance. It now covers the Redis-backed stores, which clients they work with,
  and why memory is not a default to run behind a load balancer.

  The modules table also named `mountOAuthLogin` as the fastify export — that function is Express-only; the fastify
  subpath exports `oauthLogin` and `oauthLoginPlugin`. The `./server` row listed three of its exports and omitted the
  rest.

- b9e0647: Publish only the package-root README, CHANGELOG and LICENSE.

  The `files` list matched those names at any depth rather than just the root, so a nested document was published
  alongside them — `@exortek/oauth2` shipped its `examples/README.md`. The entries are now anchored to the package root.

- 828f4ae: Fix Redis TTL and Lua handling so both supported clients behave the same.

  The internal helper that writes a key with an expiry tried the `ioredis` argument form and fell back only if it threw.
  node-redis does not throw on that form — it accepts the call and stores the key with **no expiry at all**, so the
  fallback never ran and the TTL was silently dropped. Anything given a lifetime through this path never expired on
  node-redis: OAuth 2 authorization codes, PAR request URIs and device codes among them.

  The shared counter behind `challenge` and `magic-link` rate limiting had the same problem in its Lua call, where it
  surfaced as a failure rather than silence, and let the driver's own error escape instead of the package's.

  Both now dispatch on the detected client, and counter failures are reported as the calling package's error type with a
  `code` you can branch on.

- Updated dependencies [8097e69]
- Updated dependencies [925efa8]
- Updated dependencies [b4dab8a]
- Updated dependencies [b72abf8]
- Updated dependencies [b9e0647]
- Updated dependencies [0a94f13]
  - @exortek/jwks@1.1.0
  - @exortek/jwt@1.2.3
  - @exortek/paseto@1.0.1
  - @exortek/jwe@1.0.1
  - @exortek/jwk@1.0.3
  - @exortek/jws@1.0.3

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
