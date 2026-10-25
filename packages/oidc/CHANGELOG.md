# @exortek/oidc

## 2.0.0

### Major Changes

- b54218e: OpenID Provider and relying-party hardening.
  
  - `endSessionHandler` verifies `id_token_hint` against the OP's published JWKS (or signing key) before using its `sub`; previously an unsigned hint could name any user and force their logout. Expired hints are accepted for `logout.idTokenHintMaxAge` (default `'30d'`). A `client_id` parameter must match the hint's audience, `onLogout` also receives `clientId`, and `postLogoutRedirectUris` may be a `{ [clientId]: uris }` map.
  - `handleCallback` enforces requested `max_age` (`auth_time`) and `acr_values` (`acr`), throwing the new `AUTHENTICATION_REQUIREMENTS_NOT_MET` (401). `createClient` accepts `maxAge` / `acrValues` defaults that are sent and enforced on every flow.
  - The UserInfo endpoint only reads the access token from the `Authorization` header (no `access_token` query parameter).
  - `session.cookieName` must be an RFC 6265 token and is regex-escaped in the check-session iframe.
  
  **Migration**
  
  - Publish the OP's verification keys via `jwks` (or keep the signing key), and handle `onLogout` calls with `sub: undefined` for unverifiable hints.
  - Send UserInfo requests with `Authorization: Bearer`.
  - If you pass `maxAge` / `acrValues` to `authorize()` per call, pass the same values to `handleCallback()` (or set them on `createClient`).

### Patch Changes

- 9953042: - Duration strings whose unit is the name of an `Object.prototype` member (for example `'1constructor'`) now throw instead of resolving to `NaN`.
- 9953042: - Remote metadata fetches (JWKS, OAuth token / userinfo / discovery, OIDC end-session discovery) now keep one timeout over the request **and** the response body. Before, the timer stopped once the headers arrived, so an endpoint that stalled the body held the caller indefinitely.
  - Response bodies are size-capped while they stream rather than after they are fully buffered. OIDC end-session discovery is capped at 1 MB and its per-issuer cache keeps at most 100 issuers.
  - jwks: transport failures other than a timeout (DNS, connection reset) now surface as `FETCH_FAILED` instead of a raw `TypeError`.
- Updated dependencies [9953042]
- Updated dependencies [3b047e7]
- Updated dependencies [3b047e7]
- Updated dependencies [9953042]
- Updated dependencies [3b047e7]
- Updated dependencies [b54218e]
- Updated dependencies [9953042]
- Updated dependencies [9953042]
  - @exortek/jwks@1.1.2
  - @exortek/jwt@2.0.0
  - @exortek/oauth2@2.0.0

## 1.0.0

### Major Changes

- 9ee723a: Initial release of `@exortek/oidc` — OpenID Connect Core 1.0 on top of `@exortek/oauth2`.
  
  - **Relying party** (`@exortek/oidc/client`) — a discovery-first `createClient` that enforces the `openid` scope and reuses oauth2's verified authorization-code flow: `authorize()` (with OIDC auth-request params), `handleCallback()` returning `{ idToken, claims, userinfo }` with the id_token verified end to end (`iss`/`aud`/`nonce`/`exp`, `azp`, `at_hash`), plus `endSessionUrl()` (RP-Initiated Logout 1.0), `refresh` and `revoke`.
  - **OpenID Provider** (`@exortek/oidc/provider`) — add-ons to mount beside an `@exortek/oauth2/server` authorization server: `discoveryHandler` (a full `/.well-known/openid-configuration`), `userinfoHandler` (OIDC Core §5.3 with scope→claims release and a `claims.userinfo` policy), `jwksHandler`, `endSessionHandler` (validates `post_logout_redirect_uri`), `checkSessionHandler` + `sessionState()` (Session Management 1.0), and an `idTokenSigner` reusing oauth2's `createIdTokenSigner`.
  - **Framework adapters** — `@exortek/oidc/client/express`, `/client/fastify`, `/provider/express`, `/provider/fastify`, with `express` / `fastify` as optional peers.
  
  Server-only, built on `node:crypto`; runtime deps are `@exortek/oauth2`, `@exortek/jwt`, `@exortek/jwks`.
