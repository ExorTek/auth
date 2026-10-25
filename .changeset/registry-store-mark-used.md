---
'@exortek/jwt': patch
'@exortek/paseto': patch
---

- Redis refresh-token stores no longer rewrite the stored record when a token is rotated. The atomic `markUsed` script used to decode and re-encode the record with Redis's cjson, which turned empty arrays in the stored claims into `{}` and rounded large numbers. A record created without metadata also crashed the script.
- The "used" stamp is now stored as a top-level `usedAt` field in the record. A record stamped by an earlier version is still treated as used. During a rolling upgrade, an instance still on the old version reads a token that a new instance has rotated as unused. Finish the upgrade before relying on reuse detection across instances.
- `revokeAll` (`deleteAll`) escapes glob characters in the key prefix and fetches and deletes each SCAN page in one round trip each.
