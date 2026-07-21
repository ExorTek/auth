# @exortek/session

## 1.2.0

### Minor Changes

- **Hono + Elysia adapters removed.** The `@exortek/session/hono` and
  `@exortek/session/elysia` subpaths (added in `1.0.0`) no longer
  exist. Positioning is the classic Node stack — Express and Fastify
  only. Elysia is Bun-native in practice and Hono's edge-runtime pitch
  is a domain this stack doesn't target. Removed from `exports`,
  `peerDependencies`, and `peerDependenciesMeta`. `@exortek/session/express`
  and `@exortek/session/fastify` are unchanged. Consumers on those
  frameworks need to pin `< 1.2.0` (unmaintained) or write their own
  adapter — session's public API stays framework-agnostic.

## 1.1.0

### Minor Changes

- f659550: `deriveCsrfToken` now requires a secret of at least **32 bytes**, matching the floor `@exortek/security`'s
  CSRF module has always enforced. Shorter secrets throw `INVALID_ARGUMENT`. A 32-byte HMAC-SHA-256 secret is the
  smallest value that resists offline brute-forcing of the derived token.

  Callers passing shorter secrets (previously accepted without complaint) must lengthen them — a
  `crypto.randomBytes(32).toString('base64url')` value or any 32-plus-character string is sufficient.

## 1.0.3

### Patch Changes

- 09b6ff7: **Fail-closed when `bindTo` is set but `issue()` is called without `req`.** Previously the manager would
  happily mint a session with no fingerprint, and `verify()` — seeing `payload.fp` undefined — would silently skip the
  binding check. Any application that relied on `bindTo` for defence-in-depth could lose it if a code path called
  `issue()` without threading the request through (admin scripts, background jobs, refactored middlewares). The manager
  now throws `SessionError { code: INVALID_ARGUMENT }` with a message naming the missing `options.req` and explaining
  why.

## 1.0.2

### Patch Changes

- **Fix broken install: `1.0.1` shipped with `"@exortek/crypto": "workspace:^"` in its `dependencies`, which
  `npm install` cannot resolve (`EUNSUPPORTEDPROTOCOL`).** The root release script now goes through `yarn npm publish`,
  which rewrites Yarn's workspace protocol to a real semver range at pack time. This release lists `@exortek/crypto` as
  `^1.0.6` and installs cleanly. No code changed — please upgrade `1.0.1 → 1.0.2` to unblock installs.

## 1.0.1

### Patch Changes

- de29e24: - Fastify adapter JSDoc referred to `reply.setSession` / `reply.clearSession`; the actual decorated methods
  are `reply.setSessionCookie` / `reply.clearSessionCookie`. JSDoc realigned so IDE hints match the runtime API.
  - Build hygiene: `build` / `clean` now also remove `tsconfig.tsbuildinfo` so `tsc --incremental` cannot leave stale
    `.d.ts` artifacts behind.
- Updated dependencies [eaf7921]
  - @exortek/crypto@1.0.6

## 1.0.0

### Major Changes

- 77007e2: Initial release of `@exortek/session`.

  Sealed-cookie session manager built on `@exortek/crypto.seal`. Ships every session concern a backend actually needs,
  opt-in via config flags so callers pay only for what they use.

  **Core (default on):**

  - Sealed cookie via `crypto.seal` — stateless verify hot-path
  - Cookie + `Authorization: Bearer` header extraction
  - Absolute + rolling idle TTL
  - Multi-secret rotation
  - In-process memory store with LRU eviction and background sweep
  - Per-request cache — 3 `verify(req)` calls → 1 decrypt
  - `issue` / `verify` / `rotate` / `touch` / `revoke` / `revokeById` / `revokeAllForUser` / `revokeAllExceptCurrent` /
    `listActive`
  - `deriveCsrfToken` / `verifyCsrfToken` — session-bound synchroniser tokens
  - `SessionError` + 14 stable error codes

  **Opt-in features:**

  - **Anonymous / guest sessions** with `anonymous: true`
  - **Concurrent session limit** — 3 devices max, oldest kicked
  - **Fingerprint binding** — `bindTo: ['ip', 'ua']`; mismatch → hard revoke
  - **Impersonation** — admin-as-user with `impersonatedBy` audit trail
  - **Device labels** — `iPhone 14 · Chrome` from the UA
  - **Session events** — `onIssue`, `onVerify`, `onRotate`, `onRevoke`, `onDeny`, `onSuspicious` callbacks
  - **Suspicious activity detection** — IP change flagging
  - **Sudo mode / step-up authentication** — `requireFreshAuth` + `markFresh`
  - **Remember-me** — doubles the absolute TTL on issue

  **Subpaths:**

  - `@exortek/session/stores/redis` — Redis session store with optional `publishRevocations: true` pub/sub for
    cross-worker cache invalidation. Works with `ioredis` or `node-redis@4+`.
  - `@exortek/session/trusted-device` — separate long-lived HMAC-authenticated cookie for "remember this device" 2FA
    skip. Multi-secret rotation.
  - `@exortek/session/fastify` — plugin with `req.session` + `req.sessions` + `reply.setSessionCookie` /
    `reply.clearSessionCookie`
  - `@exortek/session/express` — middleware with the same shape
  - `@exortek/session/hono` — middleware setting `c.get('session')`, `c.get('sessions')`
  - `@exortek/session/elysia` — plugin using `derive` to inject `session` + `sessions` onto the context

  **Compliance impact** — the following OWASP ASVS V3 rows on `docs/compliance.md` move from 🟡 to ✅:

  - V3.2 Session token via CSPRNG
  - V3.4 Secure / HttpOnly / SameSite cookie flags
  - V3.5 `__Host-` prefix binding
  - V3.7 Server-side invalidation on logout

  **144 unit tests** — errors, cookie, header, token round-trip, memory + Redis stores, manager
  (issue/verify/revoke/rotate/touch), sudo mode, fingerprint, device labels, impersonation, events, suspicious activity,
  CSRF derivation, trusted-device, and the four framework adapters via mocks.

### Patch Changes

- Updated dependencies [31a1159]
  - @exortek/crypto@1.0.5
