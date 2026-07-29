# @exortek/opaque

## 1.0.2

### Patch Changes

- e53ae64: Fix polynomial-ReDoS (quadratic regex backtracking) surfaced by CodeQL, plus small code-quality fixes.
  Bundled `@exortek/shared` utilities (base32, base64, duration) are inlined into the packages listed above, so each
  ships the fix.

  - Replace `/=+$/` trailing-padding strips (base32 / base64 decode, OTP provisioning URI) with linear scans —
    `"=".repeat(n) + "x"` was O(n²).
  - Rework the duration parser regex so surrounding whitespace can no longer cause O(n²) matching (trim first, single
    interior `\s*`).
  - Strip trailing spaces/dots in filename sanitisation with a linear scan — upload filenames are attacker-controlled.
  - Cap email length before the regex in magic-link.
  - Thread the JWT decode label into error messages (removes dead arguments and gives failures which segment broke).
  - Drop a duplicate character in a UA browser-detection regex character class.

  DoS-hardening and hygiene only — no API or behavioural change for valid input.

- Updated dependencies [e53ae64]
  - @exortek/crypto@1.0.9

## 1.0.1

### Patch Changes

- 69b2723: Hardening + handler refactor for the RFC 7662 / RFC 7009 endpoints.

  **BREAKING (handler shape).** Landing four days after 1.0.0 with no known external consumers of the old shape, so this
  stays a patch.

  - `introspectionHandler` and `revocationHandler` now return `{ status, body, headers }` instead of writing directly to
    the response. The caller writes the response themselves — `res.set(headers).status(status).json(body)` on Express,
    `reply.headers(headers).code(status)` + `return body` on Fastify — so they can add CORS, envelope the body, log, or
    unit-test without a fake response object. Returned headers already include the RFC-recommended defaults
    (`Content-Type: application/json`, `Cache-Control: no-store`, `Pragma: no-cache` — RFC 6749 §5.1).
  - `revocationHandler` now correctly returns `200 {}` — RFC 7009 §2.2 requires `200 OK` for both a successful revoke
    AND an invalid token ("invalid tokens do not cause an error response since the client cannot handle such an error in
    a reasonable way"). The previous 204 was spec-noncompliant.

  **Fixes.**

  - No-oracle contract holds under store failure: both handlers wrap `store.get` / `store.delete` in try/catch and
    return the same no-oracle default rather than surfacing a stack-trace 500.
  - New `HandlerOptions.onError?: (err) => void` so the app can still log the failure.
  - `create({ expiresIn })` parses the duration once and forwards the ms value to the store, removing drift between the
    returned `expiresAt` and the store's TTL.
  - `customStore` normalises non-void `set` returns (a native `Map.set` returns the Map — no longer leaks as
    `Promise<Map>`).
  - Example servers only echo `err.message` for `OpaqueError`; anything else rethrows to the framework's error handler.

  **Additions.**

  - `memoryStore().stop()` is now public (was underscore-prefixed `_stop`), for graceful shutdown / per-request stores
    in tests.

  **Docs / tests.**

  - Disambiguation banner: this package is opaque **reference tokens** (RFC 6749 §1.4 / RFC 7662), not the OPAQUE PAKE
    protocol.
  - Both endpoints MUST be authenticated (RFC 7662 §2.1 / RFC 7009 §2.1) — README, introspection docs, and compliance
    mapping now say so with a minimal `express-basic-auth` gate example.
  - Metadata is echoed verbatim by introspection; steer callers to RFC 7662 §2.2 claim names, away from PII/secrets.
  - Wire-format note: handler reads a parsed JSON body; how to accept form-encoded input (Express
    `express.urlencoded()`, Fastify `@fastify/formbody`).
  - CHANGELOG for 1.0.0 completed to list the full exported surface (`OpaqueError`, `ErrorCode`, HTTP handlers,
    `/stores` subpath).
  - New tests: non-default `hashAlgo` round-trip, `create` returns `hash === hashFn(token)`, store keys are hashes (not
    raw tokens), handler returns 200 `{ active: false }` under a throwing store, `tokenField: 'access_token'`
    custom-field flow, headers isolation per call.

## 1.0.0

### Major Changes

- 227abe3: Initial release. Opaque reference tokens for Node.js 22+ — random, unstructured tokens with no embedded
  payload.

  - Core API: `generate` / `create` / `verify` / `revoke` / `mask`
  - Errors: `OpaqueError`, `ErrorCode`
  - HTTP handlers: `introspectionHandler` (RFC 7662), `revocationHandler` (RFC 7009), framework-agnostic (raw Node,
    Express, Fastify)
  - Subpath `@exortek/opaque/stores`: `memoryStore`, `redisStore`, `customStore` (validates a user-supplied
    `OpaqueStore` implementation at construction time)
  - Zero non-`@exortek/*` runtime dependencies
