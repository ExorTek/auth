# @exortek/auth

## 2.0.0

### Major Changes

- c83515f: - Re-exports the new majors of `challenge`, `crypto`, `jwe`, `jwt`, `magic-link`, `oauth2`, `oidc`, `opaque`, `paseto`, `passkey`, `password`, `security` and `session`. These majors carry security fixes from a repo-wide audit, and several make an unsafe default an error.
  - The umbrella's own surface is unchanged: it still re-exports every package as a namespace and from each subpath.
  
  **Migration:** follow the **Migration** notes in each re-exported package's CHANGELOG for this release. The changes most likely to affect existing code:
  - PASETO keys are now typed (`keys.local(...)` / `keys.secret(...)` / `keys.public(...)`).
  - crypto, session and trusted-device secrets must be at least 32 bytes.
  - `session` impersonation requires an authorize hook.
  - opaque tokens are random-only and `create()` requires `expiresIn`.
  - `challenge` single-use tokens must be consumed.
  - `magic-link` normalizes email addresses.
  - `passkey` binds each credential to its user.
  - `security`'s `getClientIp` follows Express trust-proxy semantics.
  - The oauth2 server restricts dynamic client registration and scopes.

### Patch Changes

- Updated dependencies [d370002]
- Updated dependencies [d370002]
- Updated dependencies [ef623b3]
- Updated dependencies [9953042]
- Updated dependencies [3b047e7]
- Updated dependencies [3b047e7]
- Updated dependencies [3b047e7]
- Updated dependencies [3b047e7]
- Updated dependencies [3b047e7]
- Updated dependencies [d370002]
- Updated dependencies [9953042]
- Updated dependencies [3b047e7]
- Updated dependencies [b54218e]
- Updated dependencies [b54218e]
- Updated dependencies [d370002]
- Updated dependencies [d370002]
- Updated dependencies [3b047e7]
- Updated dependencies [d370002]
- Updated dependencies [9953042]
- Updated dependencies [d370002]
- Updated dependencies [9953042]
- Updated dependencies [9953042]
- Updated dependencies [7264d17]
- Updated dependencies [ef623b3]
- Updated dependencies [9953042]
  - @exortek/apikey@1.2.0
  - @exortek/challenge@2.0.0
  - @exortek/crypto@2.0.0
  - @exortek/jwe@2.0.0
  - @exortek/jwks@1.1.2
  - @exortek/jwt@2.0.0
  - @exortek/magic-link@3.0.0
  - @exortek/oauth2@2.0.0
  - @exortek/oidc@2.0.0
  - @exortek/opaque@2.0.0
  - @exortek/paseto@2.0.0
  - @exortek/security@2.0.0
  - @exortek/session@2.0.0
  - @exortek/jwk@1.0.5
  - @exortek/jws@1.1.0
  - @exortek/otp@1.1.5
  - @exortek/passkey@2.0.0
  - @exortek/password@2.0.0
  - @exortek/ua@1.0.4

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
