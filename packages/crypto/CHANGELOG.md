# @exortek/crypto

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
