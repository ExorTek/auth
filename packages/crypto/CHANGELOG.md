# @exortek/crypto

## 1.1.0

### Minor Changes

- b827c5c: `base64url.decode` now rejects non-canonical input.

  Node ignores the unused low bits of a final base64url character, so several distinct strings decoded to identical
  bytes — `'aGVsbG8'`, `'aGVsbG9'`, `'aGVsbG-'` and `'aGVsbG_'` all produced `"hello"`. Anything keyed on the encoded
  form, such as a deny list, a dedupe set or a replay cache, would treat one value as several.

  `decode` now accepts only the canonical spelling of the bytes and raises `INVALID_ENCODING` otherwise. Padding is
  still accepted, and anything produced by `base64url.encode` still round-trips.

  **This is a behaviour change.** Input your callers previously got bytes back for may now throw. If you accept
  base64url from an external source and want the old leniency, re-encode from the decoded bytes before comparing.

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

## 1.0.9

### Patch Changes

- e53ae64: Fix polynomial-ReDoS (quadratic regex backtracking) surfaced by CodeQL, plus small code-quality fixes.
  Bundled `@exortek/shared` utilities (base32, base64, duration) are inlined into the packages listed above, so each
  ships the fix.

  - Replace `/=+$/` trailing-padding strips (base32 / base64 decode, OTP provisioning URI) with linear scans —
    `"=".repeat(n) + "x"` was O(n²).
  - Rework the duration parser regex so surrounding whitespace can no longer cause O(n²) matching (trim first, single
    interior `\s*`).
  - Strip trailing spaces/dots in filename sanitisation with a linear scan — upload filenames are attacker-controlled.
  - Cap email length before the regex in magic-link.
  - Thread the JWT decode label into error messages (removes dead arguments and gives failures which segment broke).
  - Drop a duplicate character in a UA browser-detection regex character class.

  DoS-hardening and hygiene only — no API or behavioural change for valid input.

## 1.0.8

### Patch Changes

- 689cf87: Remove workspace-only `devDependencies` from published package.json — `@exortek/shared` no longer appears as
  `"0.0.0"` on the npm registry.

## 1.0.7

### Patch Changes

- Internal refactor: argument guards bind through `@exortek/shared/asserts` via `internal/guards.js`; timing-safe
  compare, byte helpers, Crockford codec, and rejection-sampling primitives now delegate to the shared package. No
  public API change; all exports behave identically.

## 1.0.6

### Patch Changes

- eaf7921: Build hygiene: `build` and `clean` scripts now remove `dist/` **and** `tsconfig.tsbuildinfo` before every
  build. Without the pre-clean, `tsc --incremental` could skip regenerating type declarations for removed/renamed source
  files, leaving stale `.d.ts` artifacts inside `dist/` — which `files: ["dist"]` would then ship in the tarball.

## 1.0.5

### Patch Changes

- 31a1159: `seal`/`unseal` now cache the HKDF-derived encryption key when the secret is a string, so the derivation runs
  once per string secret instead of on every call. Session verify is the hot path here — this cuts one HMAC-SHA-256 per
  token roundtrip.

  Buffer / Uint8Array secrets are deliberately not cached: their contents can be mutated (zeroised) after the fact, and
  an identity-keyed cache would then serve a key for material that no longer exists. Deployments that need caching
  should pass a string secret.

  The cache holds at most 8 entries; realistic rotation windows use 1-3 concurrent secrets so eviction is a safety
  valve, not a steady-state path.

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
