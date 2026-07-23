# @exortek/jwks

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
