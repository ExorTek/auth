# @exortek/jwks

> JSON Web Key Set (RFC 7517 §5) for Node.js 22+ — local key set with zero-downtime rotation, remote JWKS URI fetching with kid-miss refetch, HTTP handler for `/.well-known/jwks.json`. Zero non-`@exortek/*` runtime dependencies. Built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/jwks.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jwks)
[![node](https://img.shields.io/node/v/@exortek/jwks.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/jwks)](https://packagephobia.com/result?p=@exortek/jwks)
[![license](https://img.shields.io/npm/l/@exortek/jwks.svg?color=blue)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)

Two complementary halves:

- **Local key set** — generate keys, sign, rotate with grace period, serve the public JWKS.
- **Remote JWKS** — fetch, cache, auto-refetch on kid miss, resolve `(header) → KeyObject` for `@exortek/jwt` and `@exortek/jws` verify.

## Install

```bash
npm i @exortek/jwks
# or
yarn add @exortek/jwks
```

Node.js 22 LTS or newer.

## Quick start

### Local key set (signing side)

```js
import { createLocalKeySet } from '@exortek/jwks/local';

const ks = await createLocalKeySet([
  { alg: 'ES256', kid: 'sig-2024' },
]);

// Sign with the active key
const { kid, alg, privateJwk } = ks.getSigningKey('ES256');

// Serve /.well-known/jwks.json (Node.js / Express / Fastify)
app.get('/.well-known/jwks.json', ks.handler());

// Zero-downtime rotation
const newKey = await ks.rotate({ alg: 'ES256' });
// Old key stays in the JWKS for 24h (default grace period) so
// in-flight tokens signed with it can still verify.
```

### Remote JWKS (verifying side)

```js
import { createRemoteJWKS } from '@exortek/jwks/remote';
import { verify } from '@exortek/jwt';

const resolver = createRemoteJWKS(
  'https://auth.example.com/.well-known/jwks.json',
);

// Pass as the key resolver — fetches and caches automatically
const { payload } = await verify(token, resolver);
```

## API — Local key set

### `createLocalKeySet(specs, options?)`

```ts
createLocalKeySet(
  specs: KeySpec[],       // [{ alg: 'ES256', kid?: 'sig-2024', curve?, modulusLength? }]
  options?: {
    gracePeriod?: string | number,  // default '24h' — how long a retired key stays
  },
): Promise<LocalKeySet>
```

Supported algorithms: `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `EdDSA`.

Returns a `LocalKeySet` with:

| Method / Property | Description |
|---|---|
| `toJSON()` | Public JWK Set `{ keys: [...] }` — safe for JSON.stringify |
| `getSigningKey(alg?)` | Active signing key entry (newest non-retired matching `alg`) |
| `kids` | All kid values (active + grace-period retired) |
| `size` | Key count (active + grace-period retired) |
| `rotate(options)` | Retire current key for `alg`, generate replacement |
| `addKey(privateJwk)` | Import an existing key pair (must have `kid` and `alg`) |
| `handler(options?)` | HTTP handler `(req, res) => void` for `/.well-known/jwks.json` |
| `resolve(header)` | `async ({ kid, alg? }) => KeyObject` — resolver for verify |

#### `handler(options?)`

Returns a plain `(req, res) => void` using Node.js `http.ServerResponse` API (`writeHead` + `end`), which works on raw Node, Express, and Fastify.

```ts
handler({
  cacheControl?: string,  // default 'public, max-age=300'
}): (req, res) => void
```

#### `resolve(header)`

Resolver function compatible with `jwt.verify(token, resolver)`. Looks up by `kid`, validates `alg` if provided.

```js
const key = await ks.resolve({ kid: 'sig-2024', alg: 'ES256' });
```

## API — Remote JWKS

### `createRemoteJWKS(uri, options?)`

```ts
createRemoteJWKS(
  uri: string,                      // must be https (or http with allowInsecure)
  options?: RemoteJWKSOptions,
): Resolver & { reload, cachedKids }
```

Options:

| Option | Default | Description |
|---|---|---|
| `cacheTtl` | `'10m'` | Cache lifetime (ms or duration string) |
| `maxCacheKeys` | `100` | Max cached KeyObjects (LRU eviction) |
| `cooldownMs` | `10000` | Min ms between refetches on kid-miss |
| `timeout` | `5000` | Fetch timeout in ms |
| `allowInsecure` | `false` | Allow `http://` URIs |
| `staleWhileError` | `false` | Serve stale cache when refetch fails |
| `signal` | — | `AbortSignal` forwarded to fetch |
| `headers` | — | Extra headers on the fetch request |
| `onInvalidKey` | — | `(header, error) => void` — called on kid-not-found or alg mismatch |

The returned resolver has `async (header) => KeyObject` signature plus:

- **`reload()`** — force-clear cache and refetch.
- **`cachedKids()`** — kid values currently in cache.

#### Caching and kid-miss refetch

On the first call (or after `cacheTtl` expires) the JWKS is fetched. Subsequent resolves hit the in-memory cache. When a `kid` is not in cache, the endpoint is re-fetched once (rate-limited by `cooldownMs`) to handle provider-side key rotation without waiting for TTL expiry.

Concurrent callers coalesce onto a single in-flight fetch — no thundering herd.

#### Stale-while-error

When `staleWhileError: true`, a failed refetch serves keys from the previous successful fetch instead of throwing. First-time failures (no cache at all) still throw.

```js
const resolver = createRemoteJWKS('https://auth.example.com/jwks', {
  staleWhileError: true,
});
// If auth.example.com goes down, cached keys keep working until cacheTtl expires
```

## Integration with `@exortek/jwt`

```js
import { sign, verify } from '@exortek/jwt';
import { createLocalKeySet } from '@exortek/jwks/local';
import { createRemoteJWKS } from '@exortek/jwks/remote';

// Signing side
const ks = await createLocalKeySet([{ alg: 'ES256' }]);
const { kid, alg, privateJwk } = ks.getSigningKey();
const token = await sign({ sub: 'usr_123' }, privateJwk, { kid, alg });

// Verifying side
const resolver = createRemoteJWKS('https://auth.example.com/.well-known/jwks.json');
const { payload } = await verify(token, resolver);
```

## Errors

```js
import { JwksError, ErrorCode } from '@exortek/jwks';

// ErrorCode.INVALID_ARGUMENT — bad options (status 400)
// ErrorCode.FETCH_FAILED     — network/response error (status 502)
// ErrorCode.KID_NOT_FOUND    — no matching key (status 401)
```

Branch on `err.code`, never on the message.

## When to reach for something else

- **You need to generate/import/export individual JWK key pairs.** Use `@exortek/jwk`.
- **You need to sign or verify JWTs.** Use `@exortek/jwt` — pass a JWKS resolver as the key argument.
- **You need raw JWS sign/verify.** Use `@exortek/jws`.

## License

MIT
