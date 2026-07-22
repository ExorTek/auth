# @exortek/jws

## 1.0.1

### Patch Changes

- Internal refactor: errors extend the shared `BaseError`; `base64url`, `algorithms`, `crit`, `ecdsa`, `resolver`,
  and `keys.js` delegate to `@exortek/shared`; argument guards bind through `@exortek/shared/asserts` via
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
