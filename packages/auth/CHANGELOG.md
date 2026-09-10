# @exortek/auth

## 1.0.0

### Major Changes

- 2029de0: Initial release of `@exortek/auth` — the umbrella package.
  
  `@exortek/auth` re-exports every `@exortek/*` primitive from a single install:
  JWT, JWE, JWS, JWK, JWKS, PASETO, password hashing, OTP, passkeys, magic links,
  opaque tokens, sessions, API keys, OAuth 2.1, OpenID Connect, the defensive HTTP
  layer, and UA/bot detection.
  
  - **Namespace imports** — `import { jwt, password, oauth2 } from '@exortek/auth'`
    exposes each leaf package as a namespace object.
  - **Subpath forwarding** — every subpath a leaf package publishes is forwarded
    under a matching path, e.g. `@exortek/auth/jwt/token-pair`,
    `@exortek/auth/oauth2/providers/google`, `@exortek/auth/security/fastify`.
  - **Pure re-export** — every export is a thin `export * from '@exortek/<pkg>'`
    shim referencing the same module objects the leaf packages expose. No
    aggregating API, no renamed bindings, nothing inlined; bundlers tree-shake
    each subpath independently. Types are emitted for every namespace and subpath.
  
  `express` and `fastify` are optional peers, needed only when importing a
  framework adapter subpath.
