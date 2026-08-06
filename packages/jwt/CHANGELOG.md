# @exortek/jwt

## 1.3.0

### Minor Changes

- 89aea87: Validate custom store implementations at construction time. `createStore('custom', { impl })` previously
  accepted any object and returned it verbatim, so a store missing a required method surfaced only later as a
  `TypeError` deep inside a token operation. It now asserts the impl exposes the core registry contract — `add`, `has`,
  `get`, `delete`, `deleteAll` — and throws `INVALID_ARGUMENT` immediately when one is missing (`markUsed` stays
  optional, since only refresh-token rotation calls it).

  Behaviour change: an incomplete custom store that happened to work — because the missing method was never exercised —
  is now rejected up front. Complete implementations are unaffected and are still returned verbatim (no wrapping).

### Patch Changes

- 89aea87: Ship self-contained TypeScript declarations. Every package's emitted `.d.ts` referenced `@exortek/shared`
  (e.g. `import { BaseError } from '@exortek/shared/errors'`), but `@exortek/shared` is a private, never-published
  workspace package that is inlined into each bundle at build time. A TypeScript consumer therefore hit
  `Cannot find module '@exortek/shared/…'` (with `skipLibCheck` off) or silently degraded error-class types like
  `ApiKeyError` — losing its constructor signature and `.code` / `.message` — with `skipLibCheck` on.

  The build now runs a declaration-bundling pass (`rollup-plugin-dts`) after `tsc`, flattening each entry's `.d.ts` and
  inlining the `@exortek/shared` types so the shipped declarations are fully self-contained. Runtime deps and `node:*`
  stay external. No runtime or API change — types only.

## 1.2.3

### Patch Changes

- 925efa8: Fix the Redis store's client detection so the blacklist and refresh registry work with both supported
  clients.

  `createStore('redis', …)` identified an `ioredis` client by its constructor name, which never matches a real instance
  — so every ioredis client took the node-redis code path and `add()` sent the wrong `SET` argument form. Separately,
  `markUsed()` ignored the detected dialect entirely and always used the ioredis `eval` form, which node-redis accepts
  but executes with no keys. Detection now probes the client's API surface, `markUsed()` branches like the rest of the
  store, and `deleteAll()` seeds its `SCAN` cursor as a string (node-redis requires this from v6, which the declared
  peer range admits).

  If you previously worked around this by passing `dialect` explicitly, that option still works and still takes
  precedence.

- b9e0647: Publish only the package-root README, CHANGELOG and LICENSE.

  The `files` list matched those names at any depth rather than just the root, so a nested document was published
  alongside them — `@exortek/oauth2` shipped its `examples/README.md`. The entries are now anchored to the package root.

- 0a94f13: Smaller bundles — the internal argument-guard helpers are now tree-shakeable.

  Each package bundles the guard helpers it uses. They were previously built as one object holding all fourteen, which a
  bundler cannot take apart, so every package shipped all of them regardless of how many it called. They are now
  individually importable, and each package pulls in only what it uses.

  No API change: the errors, codes and messages raised by argument validation are identical. Published bundles shrink by
  roughly 7-18% depending on the package.

## 1.2.2

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

## 1.2.1

### Patch Changes

- 689cf87: Remove workspace-only `devDependencies` from published package.json — `@exortek/shared` no longer appears as
  `"0.0.0"` on the npm registry.

## 1.2.0

### Minor Changes

- 48f1b5e: Add atomic `markUsed()` to memory and redis stores (Lua CAS on Redis). `tokenPair.rotate()` now uses it for
  cross-process safe reuse detection. Custom stores without `markUsed` fall back to the existing in-process mutex.

### Patch Changes

- d28fbfb: Add `options.dialect` (`'ioredis' | 'node-redis'`) to `createRedisStore` so wrapped/proxied Redis clients can
  bypass constructor-name auto-detection.

## 1.1.0

### Minor Changes

- `tokenPair`: `refresh.alg` is now optional on the default opaque path (`opaque: true`, the default), where it was
  previously required but decorative — random bytes never touch it. Still required when `refresh.opaque: false` (signed
  JWT refresh). Additive change; existing configs continue to work.

## 1.0.0

### Major Changes

- e984b9a: Initial release of `@exortek/jwt` — JSON Web Token for Node.js 22+. **RFC 7519** (JWT core), **RFC 8725**
  (best current practice), **RFC 9068** (OAuth 2.0 access-token profile), **RFC 6749 §10.4** (refresh-token
  reuse-detection threat model), **RFC 7518** (JWA algorithms), **RFC 8037** (Ed25519 / Ed448), **RFC 8812**
  (`secp256k1`). Zero dependencies. Server-only.

  ## Surface
  - **Core (root export):** `sign`, `verify`, `peek`, `decode`, `decodeProtectedHeader`, `JwtError`, `ErrorCode`, `jwt`
    namespace.
  - **`@exortek/jwt/token-pair`:** `tokenPair.create / .rotate / .revoke / .revokeAll` with RFC 6749 §10.4 reuse
    detection.
  - **`@exortek/jwt/stores`:** `createStore('memory' | 'redis' | 'custom', ...)` with `interval` / `lazy` / `lru` GC
    strategies for the in-process store, native TTL for Redis (both ioredis and redis@4 clients auto-detected), and a
    `custom` factory that accepts the caller's own `Store` implementation.

  ## Algorithm matrix

  HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512, ES256K, EdDSA (Ed25519 + Ed448). **`none` refused
  everywhere** — no flag can enable it. RSA modulus ≥ 2048 (RFC 7518 §3.3 / §3.5) and HMAC minimum secret bytes (RFC
  7518 §3.2) enforced across every input branch.

  ## Twelve differentiators
  1. **`tokenPair` with reuse detection** — the killer feature; no other JWT lib ships this.
  2. **Mandatory `alg` allowlist on verify** — `MISSING_ALG_ALLOWLIST` before any parsing.
  3. **`alg: 'none'` refused everywhere** — dedicated `ALGORITHM_NONE_FORBIDDEN` code.
  4. **Blacklist store** — memory + Redis + custom with three GC strategies.
  5. **Custom-fn escape hatch on every knob** — `hashFn`, `generate`, `issuer` / `audience` async predicates, encoding
     matrix, `jwtId` factory.
  6. **`typ` enforcement + RFC 9068 (`at+jwt`) preset.**
  7. **`maxAge` — iat freshness policy** for leaked-token mitigation.
  8. **`scope` validation first-class** (`requiredScopes`), reading `payload.scope` (RFC 8693 §4.2) or `payload.scp`
     (array).
  9. **`peek`** — signature-verified inspection without claim checks (audit / logging safe path).
  10. **`sign` metadata return** — `{ token, jti, expiresAt, issuedAt, alg, kid }`.
  11. **`aud` array + `iss` array on verify** — multi-tenant SaaS native; RFC 7519 §4.1.3 array-form audience handled.
  12. **PEM string + X.509 certificate input** — `fs.readFileSync('./private.pem', 'utf8')` shape works directly.

  ## Key input polymorphism

  `KeyObject` | `Buffer` / `Uint8Array` (HMAC) | **PEM string** (private / public / X.509 cert — dispatched on the
  `-----BEGIN` header) | **HMAC secret string** (UTF-8 bytes, matching `jsonwebtoken`) | JWK object | JWK array (kid
  dispatch) | `async (header) => key` resolver.

  ## Deliberate omissions
  - Callback-style API (Promise-only)
  - Synchronous `sign` / `verify`
  - `ignoreExpiration` / `ignoreNotBefore` (`peek` is the safe alternative)
  - `mutatePayload` (payload always immutable)
  - `allowInsecureKeySizes` / `allowInvalidAsymmetricKeyTypes` (footguns)
  - `zip: 'DEF'` compression
  - `x5u` URL fetch (SSRF surface)
  - SHA-1 based algorithms

  ## Tests

  **96 tests** covering the algorithm matrix, PEM / X.509 / string / Buffer / JWK / JWK-array / async-resolver key
  inputs, the full claim surface (`exp`, `nbf`, `iat`, `maxAge`, `iss` / `aud` / `sub` / `nonce` matchers,
  `requiredClaims`, `requiredScopes`, `typ`, `currentDate`), tokenPair (create / rotate / reuse-detection / grace-window
  / detectReuse-off / revoke / revokeAll), stores (memory GC strategies + custom impl + redis dialect detection), and a
  CVE-labelled security suite (CVE-2015-9235 algorithm confusion, CVE-2015-2951 `alg: 'none'`, silent-allowlist
  regressions, tamper detection, shape guards, key material minimums, DoS via `maxTokenSize`).
