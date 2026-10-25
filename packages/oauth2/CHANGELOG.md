# @exortek/oauth2

## 2.0.0

### Major Changes

- 3b047e7: `pasetoIssuer` requires typed PASETO keys (`generateKeyPair()` or `keys.secret` / `keys.public` from `@exortek/paseto`) and checks their purposes at configuration time.
- b54218e: Authorization-server and RP hardening. Several defaults are stricter, so this is a major release.
  
  **Security fixes**
  
  - Every grant caps the granted scope at the client's registered `scope` ∩ the server's `scopes`; previously a client's own `scope` replaced the server list, and the device endpoint did not validate scope at all.
  - Dynamic registration only accepts `grant_types` from `registration.allowedGrants` (default `authorization_code` + `refresh_token`), scopes the server advertises, and auth methods from `registration.allowedAuthMethods` (default: every non-mTLS method). Redirect URIs must be `https`, loopback `http`, or a reverse-domain private-use scheme, with no fragment.
  - `?_fromPar=1` no longer bypasses a PAR requirement; `request_uri` must be redeemed with the `client_id` that pushed it, and a request object pushed to PAR is verified at push time.
  - `tls_client_auth` requires a chain the TLS layer verified (`socket.authorized`) and compares the subject DN attribute by attribute.
  - Rotated refresh tokens keep the family's expiry (they previously never expired), rotation is a compare-and-set (a lost race revokes the family), and a narrowed refresh request no longer narrows the successor token.
  - Token exchange checks that the subject token was issued to / for the exchanging client (`client_id`, `aud` or `may_act`), requires the bound key for a DPoP- or certificate-bound subject token, and only exchanges for targets in `tokenExchange.audiences`.
  - Device codes keep their original expiry while polled and are redeemed exactly once.
  - A replayed authorization code revokes the refresh family it produced; introspection requires a confidential client.
  - Client JWKS resolvers are cached per server; with registration enabled, `jwks_uri` hosts on loopback / private / link-local addresses are refused unless `security.allowJwksHost` says otherwise.
  - RP: reserved authorize params (`state`, `nonce`, `redirect_uri`, `scope`, PKCE, …) can no longer be overridden via `params`; api-mode login requires a flow-session secret and every such secret must be ≥ 32 bytes; an OIDC provider must declare an `issuer`; `EMAIL_UNVERIFIED` also fires when a provider omits `email_verified`.
  
  **New**
  
  - `stores.replay` (any `incr(key, ttlMs)` store) and `createRedisReplayStore(redis)` share DPoP / client-assertion / request-object jti replay checks across nodes; `verifyDpopForResource` accepts a `replayStore`.
  - DPoP nonces are stateless; set the same `security.dpop.nonceSecret` (≥ 32 bytes) on every node.
  - `DeviceStore.redeem()` (optional) for atomic device-code redemption; `introspection.allowPublicClients`.
  
  **Migration**
  
  - List every scope a client may receive in the server's `scopes`.
  - If self-registered clients need `client_credentials`, device or token exchange, add them to `registration.allowedGrants`.
  - Replace plain-`http` (non-loopback) or single-word custom-scheme redirect URIs.
  - Add `tokenExchange: { audiences: [...] }` if you exchange tokens for a `resource` / `audience`.
  - On a bare `node:http` listener with `tls_client_auth`, pass `clientCertificateAuthorized: socket.authorized` in the request descriptor.
  - Custom refresh stores: `rotate` should resolve `false` when the token was already rotated (resolving nothing keeps the old behaviour).
  - Behind a load balancer with `dpop.nonce: true`, configure `security.dpop.nonceSecret`; add `stores.replay` for cross-node replay checks.
  - RP: give api-mode login a `secret`, make every flow-session secret ≥ 32 bytes, add an `issuer` to custom OIDC providers, and stop passing reserved keys in `authorize(..., { params })`.

### Patch Changes

- 9953042: - Duration strings whose unit is the name of an `Object.prototype` member (for example `'1constructor'`) now throw instead of resolving to `NaN`.
- 9953042: - Remote metadata fetches (JWKS, OAuth token / userinfo / discovery, OIDC end-session discovery) now keep one timeout over the request **and** the response body. Before, the timer stopped once the headers arrived, so an endpoint that stalled the body held the caller indefinitely.
  - Response bodies are size-capped while they stream rather than after they are fully buffered. OIDC end-session discovery is capped at 1 MB and its per-issuer cache keeps at most 100 issuers.
  - jwks: transport failures other than a timeout (DNS, connection reset) now surface as `FETCH_FAILED` instead of a raw `TypeError`.
- 9953042: - When a record is stored again under the same id with a different owner (`userId` / `email`), the previous owner no longer lists it, and per-owner bulk revocation (`revokeAllForUser`, `revokeByEmail`) no longer reaches it.
- Updated dependencies [9953042]
- Updated dependencies [3b047e7]
- Updated dependencies [3b047e7]
- Updated dependencies [3b047e7]
- Updated dependencies [3b047e7]
- Updated dependencies [3b047e7]
- Updated dependencies [9953042]
- Updated dependencies [3b047e7]
- Updated dependencies [9953042]
  - @exortek/jwe@2.0.0
  - @exortek/jwks@1.1.2
  - @exortek/jwt@2.0.0
  - @exortek/paseto@2.0.0
  - @exortek/jwk@1.0.5
  - @exortek/jws@1.1.0

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
