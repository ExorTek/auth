# @exortek/jws

## 1.0.4

### Patch Changes

- 89aea87: Ship self-contained TypeScript declarations. Every package's emitted `.d.ts` referenced `@exortek/shared`
  (e.g. `import { BaseError } from '@exortek/shared/errors'`), but `@exortek/shared` is a private, never-published
  workspace package that is inlined into each bundle at build time. A TypeScript consumer therefore hit
  `Cannot find module '@exortek/shared/…'` (with `skipLibCheck` off) or silently degraded error-class types like
  `ApiKeyError` — losing its constructor signature and `.code` / `.message` — with `skipLibCheck` on.

  The build now runs a declaration-bundling pass (`rollup-plugin-dts`) after `tsc`, flattening each entry's `.d.ts` and
  inlining the `@exortek/shared` types so the shipped declarations are fully self-contained. Runtime deps and `node:*`
  stay external. No runtime or API change — types only.

## 1.0.3

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

## 1.0.2

### Patch Changes

- 689cf87: Remove workspace-only `devDependencies` from published package.json — `@exortek/shared` no longer appears as
  `"0.0.0"` on the npm registry.

## 1.0.1

### Patch Changes

- Internal refactor: errors extend the shared `BaseError`; `base64url`, `algorithms`, `crit`, `ecdsa`, `resolver`, and
  `keys.js` delegate to `@exortek/shared`; argument guards bind through `@exortek/shared/asserts` via
  `internal/guards.js`. No public API change.

## 1.0.0

### Major Changes

- c78fe22: Initial release of `@exortek/jws` — JSON Web Signature for Node.js 22+. **RFC 7515** (JWS core), **RFC 7518
  §3** (JWA algorithms), **RFC 7797** (unencoded payload), **RFC 8037** (Ed25519 / Ed448), **RFC 8812** (`secp256k1`),
  **RFC 8725** (best current practices). Zero dependencies. Server-only. Pure `node:crypto`.

  Surface:

  - **Compact serialisation.** `sign(payload, key, { alg })` and `verify(token, keyish, { alg: [...] })`. Payload can be
    JSON, string, or `Buffer`. Key input is polymorphic — `KeyObject`, `Buffer` (HMAC), JWK object, JWK array with `kid`
    dispatch, or `async (header) => key`.
  - **Detached content** (RFC 7515 §F) — `signDetached` / `verifyDetached` with an empty payload segment and out-of-band
    bytes.
  - **Unencoded payload** (RFC 7797) — `sign(..., { b64: false })` with auto `crit: ['b64']` injection and `.` guard.
  - **Detached + `b64: false` together** — the canonical form for `x-jws-signature` (Open Banking) and JAdES. Signing
    input is `encHeader.rawBytes`; the emitted token still carries an empty payload segment.
  - **JSON serialisation** (RFC 7515 §7.2) — `signJson` / `verifyJson` covering both the flattened (single signer) and
    general (multi-signer) forms.
  - **UNSAFE inspection** — `decode` and `decodeProtectedHeader` for `kid` extraction before choosing a resolver.

  Algorithm matrix: **HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, ES256K, EdDSA** (Ed25519 + Ed448
  driven by key type). ECDSA signatures round-trip through the RFC 7515 §3.4 raw R‖S form.

  Five modern guarantees `jose` does not enforce out of the box:

  1. **Mandatory `alg` allowlist on verify** — omission raises `MISSING_ALG_ALLOWLIST`.
  2. **`alg: 'none'` refused everywhere** — no flag, no config; dedicated `ALGORITHM_NONE_FORBIDDEN` code.
  3. **`crit` strict by default** — unknown critical headers raise `CRIT_UNSUPPORTED`; extend via
     `knownCriticalHeaders`.
  4. **Async key resolver as a first-class input** — plain function, no `createLocalJWKSet` factory dance.
  5. **Granular `ErrorCode` enum** — 13 machine-branchable codes.

  Key-material minimums enforced at the sign / verify boundary:

  - **HMAC (RFC 7518 §3.2)** — HS256 ≥ 32 B, HS384 ≥ 48 B, HS512 ≥ 64 B.
  - **RSA (RFC 7518 §3.3 / §3.5)** — RS / PS keys with a modulus under 2048 bits are refused with `INVALID_KEY`, whether
    supplied as a `KeyObject` or a JWK.

  Tree-shakeable subpaths: `./sign`, `./verify`, `./decode`, `./json`, plus the root namespace.

  **103 tests** covering the algorithm matrix, RFC 7515 Appendix A test vectors (§A.1–§A.4), detached / `b64: false` /
  JSON round-trips (including the detached + `b64: false` combination), the resolver polymorphism surface, and a
  CVE-labelled security suite (CVE-2015-9235 algorithm confusion, CVE-2015-2951 `alg: 'none'`, silent-allowlist
  regressions, `crit` misuse, header tamper, HMAC key length, RSA-1024 refusal, DoS via `maxTokenSize`).

  **Documented 1.0 non-goals** (see the per-module web docs):

  - `b64: false` in JSON serialisation is not supported (compact + detached forms cover it).
  - `verifyJson` `kid` dispatch reads only the protected header; place `kid` there or use an async resolver.
