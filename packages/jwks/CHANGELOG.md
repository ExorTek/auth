# @exortek/jwks

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
