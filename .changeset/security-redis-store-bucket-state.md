---
'@exortek/security': patch
---

Fix the Redis rate-limit store's `get()` for token-bucket / leaky-bucket
state. The Lua `READ_SCRIPT` coerced the raw value with `tonumber`
before returning it to JS, which turned every bucket state (compact
strings like `'4.5|1234567890'`) into `nil` — the algorithms then saw
a permanently-null bucket and only the first CAS-from-absent write
ever succeeded, so a burst against a `capacity: N` token-bucket let
exactly **1** request through instead of `N`.

Return the raw stored value from the Lua script and coerce to a number
in JS only when the value parses as an integer. Numeric callers
(`sliding`, `with-ban`, `read`, `incr`) still see integer counts;
bucket algorithms now see their opaque state string.

Uncovered by the live-Redis integration test
`redis: tokenBucket concurrent burst never overspends capacity`.
