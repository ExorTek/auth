---
'@exortek/oauth2': patch
'@exortek/opaque': patch
'@exortek/challenge': patch
'@exortek/magic-link': patch
---

Fix Redis TTL and Lua handling so both supported clients behave the same.

The internal helper that writes a key with an expiry tried the `ioredis`
argument form and fell back only if it threw. node-redis does not throw on
that form — it accepts the call and stores the key with **no expiry at all**,
so the fallback never ran and the TTL was silently dropped. Anything given a
lifetime through this path never expired on node-redis: OAuth 2 authorization
codes, PAR request URIs and device codes among them.

The shared counter behind `challenge` and `magic-link` rate limiting had the
same problem in its Lua call, where it surfaced as a failure rather than
silence, and let the driver's own error escape instead of the package's.

Both now dispatch on the detected client, and counter failures are reported as
the calling package's error type with a `code` you can branch on.
