# @exortek/opaque

> Opaque reference tokens for Node.js 22+ — random, unstructured tokens with no embedded payload, memory + Redis stores, RFC 7662 introspection and RFC 7009 revocation HTTP handlers. Zero non-`@exortek/*` runtime dependencies.

[![npm](https://img.shields.io/npm/v/@exortek/opaque.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/opaque)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/opaque.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/opaque)](https://packagephobia.com/result?p=@exortek/opaque)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/opaque.svg?color=blue)](./LICENSE)

## Why

A JWT carries its own claims — anyone can decode it, even without the signing key. An **opaque token** carries nothing: it's a random string, and the only way to learn anything about it is to ask the server that issued it. That's exactly what you want for a token whose lifetime and metadata need to be revocable at any moment (OAuth access tokens, short-lived reference tokens for a mobile client, session handles) — no waiting out an `exp`, no rotating a signing key to invalidate a batch. `@exortek/opaque` ships token generation, storage-backed create/verify/revoke, and the two RFCs every OAuth-style server needs on top: introspection (RFC 7662) so a resource server can ask "is this still good?", and revocation (RFC 7009) so a client can hand a token back.

## Install

```bash
npm i @exortek/opaque
# or
yarn add @exortek/opaque
```

Node.js 22 LTS or newer.

## Quick start

```js
import { create, verify, revoke } from '@exortek/opaque';
import { memoryStore } from '@exortek/opaque/stores';

const store = memoryStore(); // or redisStore(client) for multi-worker

const { token, hash, expiresAt } = await create({
  format: 'hex',
  store,
  expiresIn: '1h',
  metadata: { userId: 'usr_123', scope: 'read write' },
});
// → token = '3f9a...'  — hand this to the client, it's shown once.
// → hash  = the SHA-256 of token — what's actually stored.

const result = await verify(token, { store });
// → { valid: true, metadata: { userId: 'usr_123', scope: 'read write' } }
// → { valid: false, reason: 'not_found' }  — unknown, expired, or revoked

await revoke(token, { store });
```

## Token format

`generate()` is the entropy layer underneath `create()` — reach for it directly when you just need a random string, not a stored/verifiable token.

```js
import { generate } from '@exortek/opaque';

generate({ format: 'hex', bytes: 32 });
// → 64 hex chars

generate({ format: 'uuid4' });
generate({ format: 'ulid' });
generate({ format: 'crockford', bytes: 16 }); // no ambiguous glyphs, human-typeable
generate({ format: 'alphanumeric', length: 24 });

// Stripe-style prefix, e.g. for a token whose type should be recognisable in logs
generate({ format: 'prefixed', prefix: 'usr' });
// → 'usr_3f9a...'  (generator defaults to 'hex')

// Semantic label + entropy, generator and separator configurable
generate({ format: 'structured', version: 'v1', type: 'ref', generator: 'ulid', separator: '.' });
// → 'v1.ref.01ARZ3NDEKTSV4RRFFQ69G5FAV'
```

| `format`                        | Output                                                     |
| -------------------------------- | ------------------------------------------------------------ |
| `hex` / `base64url` / `base58` / `crockford` | Raw entropy, `bytes` long (default 32)         |
| `ulid` / `uuid4` / `uuid7`        | Standard sortable/random identifiers                       |
| `alphanumeric`                    | `[A-Za-z0-9]`, `length` characters (default `bytes`)      |
| `prefixed`                       | `<prefix><separator><generator output>`                    |
| `structured`                     | `<version><separator><type><separator><generator output>` |

`generator` (default `'hex'`) selects which of the bare formats above produces the entropy segment for `prefixed` / `structured`.

## API

### `create(options)`

```ts
create({
  // token shape — same options as generate()
  format: OpaqueTokenFormat,
  bytes?: number, length?: number, generator?: string,
  prefix?: string, version?: string, type?: string, separator?: string,

  store: OpaqueStore,
  expiresIn?: string | number,       // omit for no expiry
  metadata?: Record<string, unknown>,
  hashAlgo?: HashAlgorithm,          // default 'sha256'
  now?: number,                      // override Date.now() for testing
}): Promise<{ token: string, hash: string, expiresAt?: Date }>
```

Only the hash is written to `store` — the raw `token` is returned once and never persisted, so a leaked store row can't be turned back into a usable token.

### `verify(token, options)`

```ts
verify(token: string, {
  store: OpaqueStore,
  hashAlgo?: HashAlgorithm,
}): Promise<
  | { valid: true, metadata: Record<string, unknown> }
  | { valid: false, reason: 'not_found' }
>
```

Never throws for a bad token — unknown, malformed, expired, and revoked all collapse to `{ valid: false, reason: 'not_found' }` (expiry and revocation are the store's job; see [Stores](#stores)).

### `revoke(token, options)`

```ts
revoke(token: string, { store: OpaqueStore, hashAlgo?: HashAlgorithm }): Promise<boolean>
```

Deletes the store entry. Idempotent — revoking twice, or a token that never existed, both return `false` the second time.

### `mask(token)`

```js
import { mask } from '@exortek/opaque';

mask('3f9ab2c1d4e5f6a7b8c9d0e1f2a3b4c5');
// → '3f9a…b4c5' — log-safe
```

## RFC 7662 / RFC 7009 HTTP handlers

Framework-agnostic — works with raw Node, Express, and Fastify (unwraps `reply.raw` automatically, same as `@exortek/jwks`'s handler). Assumes the request body is already parsed (Express `json()` middleware, Fastify's built-in JSON parsing).

```js
import { introspectionHandler, revocationHandler } from '@exortek/opaque';

// RFC 7662 — always 200, `active: false` for anything invalid so a
// caller can't distinguish "unknown" from "expired" from "revoked".
app.post('/oauth/introspect', introspectionHandler({ store }));

// RFC 7009 — always 200 with an empty body, whether or not the token
// existed, so the endpoint can't be used to probe token validity.
app.post('/oauth/revoke', revocationHandler({ store }));
```

| Option       | Default    | Notes                                    |
| ------------ | ---------- | ------------------------------------------ |
| `store`      | —          | Required.                                |
| `hashAlgo`   | `'sha256'` |                                           |
| `tokenField` | `'token'`  | Field read off the parsed request body.  |

See `@exortek/opaque/examples/express-server.js` and `fastify-server.js` for a runnable version.

## Stores

`@exortek/opaque/stores` ships two implementations. Any object matching the `OpaqueStore` interface works.

- **`memoryStore(options?)`** — in-process `Map`, lazy expiry check on `get` plus a background sweep (`sweepMs`, default 60000). Not cluster-safe. Fine for dev / single-node prod / tests.
- **`redisStore(client, options?)`** — one key per token (`<keyPrefix><hash>`), native Redis `PX` TTL. Cluster-safe. Works with `ioredis`, `node-redis@4+`, `@upstash/redis`. `options.keyPrefix` defaults to `'opaque:'`.
- **`customStore(impl)`** — wrap your own DB-backed implementation. Validates `set`/`get`/`delete` exist at construction time and wraps sync return values in a Promise.

### The interface

```ts
interface OpaqueStore {
  set(key: string, value: Record<string, unknown>, options?: { expiresIn?: string | number }): Promise<void>;
  get(key: string): Promise<Record<string, unknown> | null>; // must return null once expired
  delete(key: string): Promise<boolean>;
}
```

## Errors

```js
import { OpaqueError, ErrorCode } from '@exortek/opaque';
```

| Code               | HTTP | Raised when                                                       |
| ------------------ | ---- | --------------------------------------------------------------------- |
| `INVALID_ARGUMENT` | 400  | Options object is missing, misshapen, or violates an invariant.  |

Expected verify failures do NOT throw — they surface as `{ valid: false, reason }`. See [`verify(token, options)`](#verifytoken-options).

## Highlights

- Random, unstructured tokens — nothing to decode, only the store knows what a token means.
- `create` / `verify` / `revoke` never leak whether a token existed to the wrong caller.
- RFC 7662 introspection and RFC 7009 revocation HTTP handlers, framework-agnostic.
- Memory + Redis stores, zero non-`@exortek/*` runtime dependencies.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues & discussions:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
