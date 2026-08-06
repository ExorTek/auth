# @exortek/jwe

## 1.0.1

### Patch Changes

- b9e0647: Publish only the package-root README, CHANGELOG and LICENSE.

  The `files` list matched those names at any depth rather than just the root, so a nested document was published
  alongside them — `@exortek/oauth2` shipped its `examples/README.md`. The entries are now anchored to the package root.

- 0a94f13: Smaller bundles — the internal argument-guard helpers are now tree-shakeable.

  Each package bundles the guard helpers it uses. They were previously built as one object holding all fourteen, which a
  bundler cannot take apart, so every package shipped all of them regardless of how many it called. They are now
  individually importable, and each package pulls in only what it uses.

  No API change: the errors, codes and messages raised by argument validation are identical. Published bundles shrink by
  roughly 7-18% depending on the package.

## 1.0.0

### Major Changes

- 3465d01: Initial release of `@exortek/jwe` — JSON Web Encryption (RFC 7516 / RFC 7518 §4–§5) for Node.js 22+.

  - Compact and JSON (General + Flattened, multi-recipient) serializations.
  - Key management: `RSA-OAEP`, `RSA-OAEP-256`, `ECDH-ES` (direct + `A128KW` / `A256KW` wrap), `A128KW`, `A256KW`,
    `dir`. ECDH-ES supports EC (P-256/P-384/P-521) and X25519, deriving keys via the RFC 7518 §4.6.2 Concat KDF.
  - Content encryption: `A128GCM`, `A192GCM`, `A256GCM`, `A128CBC-HS256`, `A256CBC-HS512`.
  - Mandatory `alg` + `enc` allowlists on `decrypt`; `RSA1_5` is never accepted. Unsafe `decode` /
    `decodeProtectedHeader` for header inspection. Zero runtime dependencies, built on `node:crypto`.
