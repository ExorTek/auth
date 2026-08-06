# @exortek/jwks

## 1.1.0

### Minor Changes

- b4dab8a: Let a deployment constrain which hosts the authorization server will fetch a client's `jwks_uri` from.

  A client's `jwks_uri` is client-supplied, and the server fetches it when verifying `private_key_jwt` client assertions
  and JAR request objects. Under dynamic client registration the value is chosen by whoever registered, so the
  destination is worth constraining.

  `createServer` accepts `security.allowJwksHost`, a predicate receiving the hostname and parsed URL; returning `false`
  refuses the URI. `createRemoteJWKS` gains the same hook as `allowHost`. Both are optional and unset by default —
  existing behaviour is unchanged.

  Recommended wherever `registration` is enabled.

### Patch Changes

- 8097e69: Enforce `maxResponseSize` while the JWKS response is read, rather than after.

  The limit was checked against the `Content-Length` header and then again once the body had been read in full. A
  response that omits the header — any chunked reply — skipped the first check, so the entire body was already buffered
  by the time the second one ran and the limit had no effect on what was allocated. The body is now read incrementally
  and abandoned as soon as it crosses the limit.

- b9e0647: Publish only the package-root README, CHANGELOG and LICENSE.

  The `files` list matched those names at any depth rather than just the root, so a nested document was published
  alongside them — `@exortek/oauth2` shipped its `examples/README.md`. The entries are now anchored to the package root.

- 0a94f13: Smaller bundles — the internal argument-guard helpers are now tree-shakeable.

  Each package bundles the guard helpers it uses. They were previously built as one object holding all fourteen, which a
  bundler cannot take apart, so every package shipped all of them regardless of how many it called. They are now
  individually importable, and each package pulls in only what it uses.

  No API change: the errors, codes and messages raised by argument validation are identical. Published bundles shrink by
  roughly 7-18% depending on the package.

- Updated dependencies [b9e0647]
- Updated dependencies [0a94f13]
  - @exortek/jwk@1.0.3

## 1.0.4

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

## 1.0.3

### Patch Changes

- 40fc707: Fix `createLocalKeySet().handler()` throwing on Fastify — it called `res.writeHead`/`res.end` directly, which
  works for Express and raw Node but not Fastify, where the second handler argument is a `Reply` wrapper rather than the
  raw `ServerResponse`. Now unwraps `reply.raw` when present.

## 1.0.2

### Patch Changes

- 689cf87: Remove workspace-only `devDependencies` from published package.json — `@exortek/shared` no longer appears as
  `"0.0.0"` on the npm registry.
- Updated dependencies [689cf87]
  - @exortek/jwk@1.0.2

## 1.0.1

### Patch Changes

- 48f1b5e: Fix `cache:false` silently caching forever, harden remote fetch against SSRF (disable redirects, cap response
  at `maxResponseSize`), and fix abort-listener leak on long-lived resolvers by using `AbortSignal.any()`.

## 1.0.0

### Major Changes

- bb61d62: Initial release — JSON Web Key Set (RFC 7517 §5) for Node.js 22+.

  **Local key set** (`@exortek/jwks/local`):
  - `createLocalKeySet(specs, options?)` — generate EC/RSA/OKP keys, zero-downtime rotation with configurable grace
    period, `toJSON()` for public JWKS, `getSigningKey(alg?)`, `addKey(jwk)` with duplicate-kid guard, `resolve(header)`
    with alg cross-check.
  - `handler(options?)` — HTTP handler for `/.well-known/jwks.json` using Node.js `writeHead`/`end` API (works on raw
    Node, Express, Fastify). Configurable `Cache-Control`.

  **Remote JWKS** (`@exortek/jwks/remote`):
  - `createRemoteJWKS(uri, options?)` — fetch, cache, and resolve keys from a remote JWKS endpoint. URI protocol
    whitelist (SSRF defense), kid-miss refetch with cooldown, concurrent fetch coalescing, LRU eviction for KeyObject
    cache. `reload()` and `cachedKids()` helpers.
  - `staleWhileError` option — serve stale cached keys when refetch fails.
  - `signal` option — caller-provided `AbortSignal` forwarded to fetch.
  - `onInvalidKey(header, error)` callback — fires on kid-not-found or alg mismatch for logging/metrics.

  **Resolver pattern**: both local and remote expose `async (header) => KeyObject`, compatible with `@exortek/jwt`
  verify and `@exortek/jws` verify.
