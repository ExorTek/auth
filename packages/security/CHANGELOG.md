# @exortek/security

## 1.1.2

### Patch Changes

- a1cd6b1: `getClientIp` walks `X-Forwarded-For` **right-to-left** when `trustProxy` is an allowlist, returning the
  first untrusted hop instead of the left-most entry. The old behaviour was spoofable: an attacker could send their own
  `X-Forwarded-For: 1.2.3.4` header, a conforming proxy would _append_ the real address, and `trustProxy: ['proxy-ip']`
  still returned the attacker-controlled left-most value — bypassing rate-limit keys, poisoning IP logs, and misleading
  fingerprint binding.

  Also new: `proxyCount: N` skips **N** rightmost hops and returns the `(N + 1)`-th from the right — an
  addresses-not-known alternative to `trustProxy: string[]` for setups like Cloudflare + a k8s ingress. `proxyCount`
  wins over `trustProxy` when both are set.

  `trustProxy: true` keeps its left-most behaviour for backwards compatibility but is now documented as unsafe unless
  the first proxy strips inbound XFF headers — prefer `trustProxy: string[]` or `proxyCount` in production.

## 1.1.1

### Patch Changes

- 07233f2: Fix the Redis rate-limit store's `get()` for token-bucket / leaky-bucket state. The Lua `READ_SCRIPT` coerced
  the raw value with `tonumber` before returning it to JS, which turned every bucket state (compact strings like
  `'4.5|1234567890'`) into `nil` — the algorithms then saw a permanently-null bucket and only the first CAS-from-absent
  write ever succeeded, so a burst against a `capacity: N` token-bucket let exactly **1** request through instead of
  `N`.

  Return the raw stored value from the Lua script and coerce to a number in JS only when the value parses as an integer.
  Numeric callers (`sliding`, `with-ban`, `read`, `incr`) still see integer counts; bucket algorithms now see their
  opaque state string.

  Uncovered by the live-Redis integration test `redis: tokenBucket concurrent burst never overspends capacity`.

## 1.1.0

### Minor Changes

- 8c81799: **Rate-limit atomicity under concurrency.**

  - Stores gain two optional atomic methods: `decr(key)` (exists-guarded, clamped at zero) and
    `compareAndSet(key, expected, value, ttlMs)` (`expected: null` = key must not exist). The bundled memory and Redis
    stores implement both — Redis via Lua scripts registered alongside the existing `incr`/`read` ones. `customStore`
    passes them through when the backing implementation provides them.
  - `sliding` now rolls back a rejected request's tentative increment through atomic `decr` when available, instead of a
    read-modify-write `set` that could clobber concurrent increments and under-count the window.
  - `tokenBucket` / `leakyBucket` now write their state through `compareAndSet` in an optimistic-concurrency retry loop
    — concurrent requests can no longer double-spend a token / slot on the bundled stores. If a (broken) store's CAS
    never succeeds, the request is denied fail-closed rather than written racily. Stores without `compareAndSet` keep
    the previous last-writer-wins behavior.

  **Other fixes rolled into this release:**

  - Hono `securityMiddleware` now stamps static security headers (CSP, HSTS, etc.) **before** running CORS / rate-limit
    / CSRF, so terminal `429` / `403` responses carry them too. Matches the Express and Elysia adapters.
  - `slowDown.window` parsing now delegates to the shared rate-limit `parseDuration`, so it additionally accepts the `w`
    (week) suffix. Existing `ms` / `s` / `m` / `h` / `d` values are unchanged.
  - Build hygiene: `build` / `clean` now also remove `tsconfig.tsbuildinfo` so `tsc --incremental` cannot leave stale
    `.d.ts` artifacts behind.

## 1.0.1

### Patch Changes

- 032b70b: - **`sanitizeBody` blocks prototype poisoning unconditionally.** Keys named `__proto__`, `constructor`, and
  `prototype` are always dropped, and surviving entries are written with `Object.defineProperty` as own properties — the
  prototype chain of the sanitised output is inert even under crafted payloads.
  - **Hono / Elysia rate-limit no longer trusts `X-Forwarded-For` by default.** Without a proxy in front,
    `X-Forwarded-For` is client-controlled — trusting it lets an attacker rotate the header to mint unlimited rate-limit
    buckets. The adapters now fall back to the socket peer address unless the caller opts in with
    `rateLimit: { trustProxy: true }` or supplies a `keyGenerator` that reads their platform's trusted header
    (`CF-Connecting-IP`, `Fastly-Client-IP`, …). Fastify and Express were already safe (`req.ip` respects each
    framework's own `trustProxy` setting).
  - **`slowDown` DoS caveat documented.** The helper holds each throttled request open on `setTimeout`, so under
    sustained abuse the delay itself ties up sockets and event-loop slots. The JSDoc and web docs now spell out the
    mitigations (`http.Server.maxConnections`, `limit_conn`, chaining behind a hard rejecting limiter).

## 1.0.0

### Major Changes

- Initial release. Framework-agnostic defensive HTTP layer for Node.js 22+ — CSRF, rate limiting, helmet-style headers,
  CORS, safe redirects, and 17 focused defensive helpers. Adapters for Fastify, Express, Hono, and Elysia.

  Highlights:

  - **csrf** — signed / unsigned / session-bound tokens; HMAC + timing-safe.
  - **rate-limit** — fixed / sliding / token-bucket / leaky-bucket + `multi` combinator + `withBan` escalation policy.
    Backends: memory (true LRU), Redis (atomic Lua, `defineCommand` EVALSHA on ioredis), custom.
  - **headers** — CSP with build-time source validation, HSTS with preload-eligibility guard, COOP/COEP/CORP, Referrer,
    Permissions, frameguard, noSniff, XSS-Protection.
  - **cors** — 6 origin flavours including sync/async predicates, preflight handling, `credentials: true` guard rails.
  - **redirect** — `safeRedirect` catches every classic open-redirect vector (protocol-relative, javascript:/data:
    schemes, userinfo tricks, control chars). Ships with `extractReturnUrl` and `isSameOrigin` for typical
    login-callback flows.
  - **17 helpers** — `getClientIp`, `bearer`, `checkOrigin`, `webhookVerify`, `sanitizeBody`, `sanitizeParams`,
    `safeJoin`, `sanitizeFilename`, `freezePrototypes`, `timeout`, `bodyLimit`, `honeypot`, `slowDown`, `safeJsonParse`,
    `constantTimeEqual`, `parseCspReport`, `cspNonce`.
  - **Adapters** — Fastify, Express, Hono, Elysia. Each ships a bundle (`securityMiddleware` / `securityPlugin`) AND
    per-concern middleware so you can pick just CORS or just rate-limit.
  - **Configurable rate-limit response headers** — `'legacy'` (default), `'draft'` (RFC 9331), `false`, or a per-field
    override.

  Runtime footprint: `node:crypto` + `node:path`, plus `fastify-plugin` (~3 KB) only when the `/fastify` subpath is
  imported. Every other framework is an optional peer.

  Ships with 238 tests (237 passing + 1 Redis integration gated on `REDIS_URL`). Pure JavaScript source, TypeScript
  types generated from JSDoc.
