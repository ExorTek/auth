---
'@exortek/jwt': major
---

- `tokenPair` with `refresh.opaque: false` signs refresh tokens with `typ: refresh+jwt` and refuses a `secret.refresh` equal to `secret.access` (a refresh token under the access key verified as an access token).
- HMAC algorithms reject a PEM key or certificate with `INVALID_KEY` instead of an untyped TypeError.
- A JWK that declares `alg`, `use` or `key_ops` is only used for that alg / signatures / that operation.
- JWK objects and PEM / secret strings are imported once and reused (ES256 verify with a PEM: 48.5 → 34.3 µs); HMAC signs with the KeyObject directly and ECDSA uses IEEE P1363 natively.

**Migration:** give `tokenPair` distinct access and refresh keys when `refresh.opaque` is `false`; treat key objects as immutable once used.
