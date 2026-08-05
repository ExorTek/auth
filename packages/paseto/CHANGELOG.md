# @exortek/paseto

## 1.0.0

### Major Changes

- 9e1eb27: Initial release of `@exortek/paseto` — Platform-Agnostic Security Tokens (PASETO v4) for Node.js 22+.

  - `v4.local` — symmetric authenticated encryption (XChaCha20 + keyed BLAKE2b, encrypt-then-MAC) via `encrypt` /
    `decrypt`.
  - `v4.public` — Ed25519 signatures via `sign` / `verify`.
  - The token's `vN.purpose.` prefix binds the primitive set — there is no negotiable `alg` header, so JWT-style
    algorithm-confusion attacks are structurally impossible.
  - Registered claims as ISO 8601 datetimes (`exp` / `nbf` / `iat`) plus `iss` / `sub` / `aud`, with `clockTolerance`;
    footers and implicit assertions are authenticated.
  - `generateKey` / `generateKeyPair`; raw keys interoperate with the official PASETO wire format and Node `KeyObject`s.
  - `decode` — read a token's version / purpose / footer without a key (for `kid`-based key selection); the payload is
    never exposed unverified. Decoders reject tokens over `maxTokenSize` (default 8192 bytes) with `TOKEN_TOO_LARGE`.
  - Token-pair layer (`@exortek/paseto/token-pair`) — access + refresh with RFC 6749 §10.4 reuse detection over a
    pluggable store (`@exortek/paseto/stores`: memory, redis, custom); the access token purpose (`local` / `public`) is
    the caller's choice.
  - Verified byte-for-byte against the official PASETO v4 test vectors. Zero runtime dependencies; BLAKE2b (keyed,
    variable-length) and HChaCha20 are vendored because `node:crypto` does not expose them.
