# @exortek/jwk

## 1.0.1

### Patch Changes

- Internal refactor: errors extend the shared `BaseError`; base64url delegates to `@exortek/shared/base64url`;
  argument guards bind through `@exortek/shared/asserts` via `internal/guards.js`; `exportJWK` options validated
  through `@exortek/shared/validate`. No public API change.

## 1.0.0

### Major Changes

- f5fbbd6: Initial release of `@exortek/jwk` — JSON Web Key for Node.js 22+. **RFC 7517** (JWK), **RFC 7518 §6**
  (per-kty parameters), **RFC 8037** (Ed25519 / Ed448 / X25519 / X448), **RFC 8812** (`secp256k1`), **RFC 7638**
  (thumbprint), **RFC 9278** (thumbprint URI). Zero dependencies. Pure `node:crypto`.

  Surface:

  - `generate(kty, options)` — EC / RSA / OKP / oct, returns both public and private JWK.
  - `importJWK` / `exportJWK` — round-trips via `node:crypto.KeyObject`.
  - `importPEM(pemOrDer, 'spki' | 'pkcs8' | 'x509')` — X.509 certificate → public key supported.
  - `exportPEM` — sensible default (private→PKCS#8, public→SPKI), ambiguous combinations rejected.
  - `thumbprint(jwk, digest)` — RFC 7638 base64url digest.
  - `thumbprintURI(jwk, digest)` — RFC 9278 `urn:ietf:params:oauth:jwk-thumbprint:sha-256:…`.
  - `matches(a, b)` — thumbprint-based semantic equality across projections.
  - `toPublic(jwk)` — defensive private-member strip (drops `d` + full RSA CRT set + `oth`); throws on `oct`.
  - `validate` / `isValid` — strict RFC 7517 §4 + per-kty checks; enforces §4.3 `use`/`key_ops` consistency;
    `requirePublic` / `requirePrivate` guards.

  5 tree-shakeable subpaths plus root: `./generate`, `./import`, `./export`, `./thumbprint`, `./validate`.

  70 tests including the RFC 7638 §3.1 reference vector, all supported EC + OKP curves, and base64url edge cases.
