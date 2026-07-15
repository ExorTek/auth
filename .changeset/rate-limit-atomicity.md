---
'@exortek/security': minor
---

**Rate-limit atomicity under concurrency.**

- Stores gain two optional atomic methods: `decr(key)` (exists-guarded, clamped at zero) and `compareAndSet(key, expected, value, ttlMs)` (`expected: null` = key must not exist). The bundled memory and Redis stores implement both — Redis via Lua scripts registered alongside the existing `incr`/`read` ones. `customStore` passes them through when the backing implementation provides them.
- `sliding` now rolls back a rejected request's tentative increment through atomic `decr` when available, instead of a read-modify-write `set` that could clobber concurrent increments and under-count the window.
- `tokenBucket` / `leakyBucket` now write their state through `compareAndSet` in an optimistic-concurrency retry loop — concurrent requests can no longer double-spend a token / slot on the bundled stores. If a (broken) store's CAS never succeeds, the request is denied fail-closed rather than written racily. Stores without `compareAndSet` keep the previous last-writer-wins behavior.

**Other fixes rolled into this release:**

- Hono `securityMiddleware` now stamps static security headers (CSP, HSTS, etc.) **before** running CORS / rate-limit / CSRF, so terminal `429` / `403` responses carry them too. Matches the Express and Elysia adapters.
- `slowDown.window` parsing now delegates to the shared rate-limit `parseDuration`, so it additionally accepts the `w` (week) suffix. Existing `ms` / `s` / `m` / `h` / `d` values are unchanged.
- Build hygiene: `build` / `clean` now also remove `tsconfig.tsbuildinfo` so `tsc --incremental` cannot leave stale `.d.ts` artifacts behind.
