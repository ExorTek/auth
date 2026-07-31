# @exortek/jwe

## 1.0.0

### Major Changes

- 3465d01: Initial release of `@exortek/jwe` — JSON Web Encryption (RFC 7516 / RFC 7518 §4–§5) for Node.js 22+.

  - Compact and JSON (General + Flattened, multi-recipient) serializations.
  - Key management: `RSA-OAEP`, `RSA-OAEP-256`, `ECDH-ES` (direct + `A128KW` / `A256KW` wrap), `A128KW`, `A256KW`,
    `dir`. ECDH-ES supports EC (P-256/P-384/P-521) and X25519, deriving keys via the RFC 7518 §4.6.2 Concat KDF.
  - Content encryption: `A128GCM`, `A192GCM`, `A256GCM`, `A128CBC-HS256`, `A256CBC-HS512`.
  - Mandatory `alg` + `enc` allowlists on `decrypt`; `RSA1_5` is never accepted. Unsafe `decode` /
    `decodeProtectedHeader` for header inspection. Zero runtime dependencies, built on `node:crypto`.
