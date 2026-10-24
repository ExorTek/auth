---
'@exortek/paseto': major
---

Typed keys and token hardening.

- **Typed keys (algorithm lucidity).** `generateKey()` / `generateKeyPair()` return `PasetoKey` objects carrying version + purpose; `keys.local` / `keys.secret` / `keys.public` wrap existing material. `encrypt` / `decrypt` only take `local` keys, `sign` only `secret`, `verify` only `public` — anything else, including a bare buffer, throws the new `INVALID_KEY_PURPOSE`. Previously a v4.public public key worked as a v4.local key, so anyone holding it could mint local tokens.
- `tokenPair` passed seconds where `encrypt` / `sign` expect milliseconds: `access.expiresIn: 900` produced a token valid for 0.9 s. Token `exp` now matches the reported expiry.
- `tokenPair` with `refresh.opaque: false` refuses a refresh key equal to the access key.
- A token with an empty footer segment (trailing `.`) is rejected.
- `issuer` / `subject` / `audience` requirements reject a payload that is not a claims object.
- BLAKE2b is ~15× faster (32-bit lanes instead of BigInt).

**Migration**

- Replace raw key buffers with `keys.local(bytes)`, `keys.secret(bytes)` and `keys.public(bytes)`; persist keys with `key.export()`.
- Give `tokenPair` distinct `secret.access` and `secret.refresh` keys when `refresh.opaque` is `false`.
