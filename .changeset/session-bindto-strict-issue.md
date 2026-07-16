---
'@exortek/session': patch
---

**Fail-closed when `bindTo` is set but `issue()` is called without `req`.** Previously the manager would happily mint a session with no fingerprint, and `verify()` — seeing `payload.fp` undefined — would silently skip the binding check. Any application that relied on `bindTo` for defence-in-depth could lose it if a code path called `issue()` without threading the request through (admin scripts, background jobs, refactored middlewares). The manager now throws `SessionError { code: INVALID_ARGUMENT }` with a message naming the missing `options.req` and explaining why.
