# @exortek/challenge

## 1.0.0

### Initial release

- **`createChallenge(options)`** — issue an HMAC-signed challenge token
  carrying `userId` / `method` / `step` / `nextStep` / `metadata` across
  a multi-step auth flow. Optional `ipBinding` stamps the origin IP into
  the payload; optional `singleUse` marks the token for one-shot
  consumption via a caller-supplied store.
- **`verifyChallenge(token, options)`** — HMAC-verify, expiry-check,
  and optionally match `expectedUserId` / `expectedMethod` /
  `expectedStep` / `expectedNextStep`, plus IP match when the token was
  IP-bound. Returns `{ valid: true, payload }` on success or
  `{ valid: false, reason }` on any expected failure; never throws on
  bad tokens, only on programmer errors.
- **Stores** — ships `memoryStore()` (single-node / dev, LRU + TTL
  sweep) and `redisStore(client)` (cluster-safe, single Lua round-trip
  per verify) under the `@exortek/challenge/stores` subpath. Any object
  exposing `incr(key, ttlMs) → { count }` also works — e.g.
  `@exortek/security`'s rate-limit stores.
- **Token format:** `chall_v1.<base64url(payload)>.<base64url(hmac)>`
  — deliberately not a JWT so the two token families cannot be confused
  at a call site.
- **Errors:** stable `ErrorCode.INVALID_ARGUMENT` /
  `ErrorCode.INVALID_SECRET` codes on the `ChallengeError` class.
