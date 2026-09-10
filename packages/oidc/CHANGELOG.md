# @exortek/oidc

## 1.0.0

### Major Changes

- 9ee723a: Initial release of `@exortek/oidc` — OpenID Connect Core 1.0 on top of `@exortek/oauth2`.
  
  - **Relying party** (`@exortek/oidc/client`) — a discovery-first `createClient` that enforces the `openid` scope and reuses oauth2's verified authorization-code flow: `authorize()` (with OIDC auth-request params), `handleCallback()` returning `{ idToken, claims, userinfo }` with the id_token verified end to end (`iss`/`aud`/`nonce`/`exp`, `azp`, `at_hash`), plus `endSessionUrl()` (RP-Initiated Logout 1.0), `refresh` and `revoke`.
  - **OpenID Provider** (`@exortek/oidc/provider`) — add-ons to mount beside an `@exortek/oauth2/server` authorization server: `discoveryHandler` (a full `/.well-known/openid-configuration`), `userinfoHandler` (OIDC Core §5.3 with scope→claims release and a `claims.userinfo` policy), `jwksHandler`, `endSessionHandler` (validates `post_logout_redirect_uri`), `checkSessionHandler` + `sessionState()` (Session Management 1.0), and an `idTokenSigner` reusing oauth2's `createIdTokenSigner`.
  - **Framework adapters** — `@exortek/oidc/client/express`, `/client/fastify`, `/provider/express`, `/provider/fastify`, with `express` / `fastify` as optional peers.
  
  Server-only, built on `node:crypto`; runtime deps are `@exortek/oauth2`, `@exortek/jwt`, `@exortek/jwks`.
