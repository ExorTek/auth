---
'@exortek/session': major
---

- Session and trusted-device secrets must be at least 32 bytes each, checked at configuration time.
- `impersonation: true` requires `impersonationAuthorize({ admin, targetUserId, reason, req })`; a refusal is the new `FORBIDDEN` (403). A per-call `ttl` can shorten but never exceed `impersonationTtl`.
- `createTrustedDeviceCookie` accepts `revokedBefore(userId)` for server-side revocation of trusted-device cookies.
- The memory store evicts in O(1) at capacity (72 → 2.6 µs per insert on a full 10k store); the Redis store skips the re-read on the rolling touch and writes record + index in parallel. Store `update()` takes an optional third `current` argument.

**Migration:** use ≥ 32-byte secrets, and add an `impersonationAuthorize` hook if you enable impersonation.
