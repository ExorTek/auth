# @exortek/crypto

## 1.0.4

### Patch Changes

- a6a1e6b: - **HKDF `length` bound respects the chosen hash.** The 255 × hashLen limit is now computed against the real
  hash output size (SHA-256 → 8160, SHA-384 → 12240, SHA-512 → 16320) instead of the hard-coded SHA-512 ceiling. Calls
  that would previously slip past validation and surface a raw Node `RangeError` are now rejected with
  `CryptoError(INVALID_ARGUMENT)`, matching the rest of the package's error contract.
  - **`unseal` accepts a secret array for rotation.** Pass `[newest, …older]` as the second argument; each key is tried
    in order and the first that authenticates wins. Enables graceful key rotation without invalidating tokens minted
    under the previous secret. Backwards-compatible — a bare secret still works exactly as before.

## 1.0.3

### Patch Changes

- Ships the `dist/*.mjs` / `dist/*.cjs` bundles unminified for auditability. Consumers can now read the shipped code in
  `node_modules`, stack traces reference real function names (`fingerprint`, `assertEncoding`) instead of mangled
  one-letters, and supply-chain tools (Socket, Snyk) can parse the tarball without heuristics. Follows the convention
  set by jose, jsonwebtoken, zod, drizzle, and every other serious Node auth library. Tarball grows from ~68 kB to ~222
  kB — well within reason for a Node library.

## 1.0.2

### Patch Changes

- Replaces terse error messages across the whole surface with actionable ones that name what the caller passed and point
  at the fix. Example: `cipher.encrypt(data, promise)` now throws
  `key must be a KeyObject; got a Promise — did you forget "await"?`. Every message change is text only — no `ErrorCode`
  renames, no API changes.

## 1.0.1

### Patch Changes

- Slim published tarball — apply Terser to the CJS output (previously only ESM was minified) and drop `.map` sourcemap /
  `.d.ts.map` declaration-map files. No runtime behaviour change. Package tarball drops from ~140 kB to ~68 kB.

## 1.0.0

### Major Changes

- Initial release — hash, HMAC, KDFs, AEAD ciphers, asymmetric signatures, sealed timed tokens, CSPRNG, and encoders,
  all built on node:crypto.
