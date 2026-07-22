# @exortek/apikey

> Stripe-style prefixed API keys for Node.js 22+ — 3-segment tokens (`sk_live_<id>_<secret>`), HMAC-SHA256 storage hash with optional pepper rotation, scope allowlists, memory + Redis stores, Express + Fastify middleware. Zero non-`@exortek/*` runtime dependencies.

[![npm](https://img.shields.io/npm/v/@exortek/apikey.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/apikey)
[![node](https://img.shields.io/node/v/@exortek/apikey.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/apikey)](https://packagephobia.com/result?p=@exortek/apikey)
[![license](https://img.shields.io/npm/l/@exortek/apikey.svg?color=blue)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)

Every API vendor rebuilds the same six things: a prefixed token format so keys are recognisable in logs, hashed storage so a leaked DB doesn't leak secrets, scope allowlists so a machine token can't accidentally admin your infrastructure, revocation, a per-user list for the "manage API keys" UI, and a middleware that turns `Authorization: Bearer <key>` into a verified caller identity. `@exortek/apikey` ships all six.

## Install

```bash
npm i @exortek/apikey
# or
yarn add @exortek/apikey
```

Node.js 22 LTS or newer. Optional: `express` or `fastify` peer deps for the shipped middleware.

## Token format

```
sk_live_A2X4KJRK5HYFR3E7CBEQZP9WTN_QM5K3EHRSPMY8TDN4GRFB2CGY6VJE1BW7FRXK8ZHDNA9TPY5CV6QM
   ^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   type  id — 128-bit, plaintext    secret — 256-bit, HMAC-SHA256 for storage
         (O(1) DB primary-key lookup)
```

Three underscore-separated segments. **id** and **secret** use base32-crockford (`[0-9A-HJKMNP-TV-Z]`) — no ambiguous glyphs, no separators, safe in URLs and audit logs. **prefix** is Stripe-style: lowercase alpha + digits + underscore-separated segments (`sk_live`, `pk_test`, `svc_prod_v2`).

The **id** is plaintext because it isn't a secret — an attacker who guesses an id alone still fails the HMAC compare on the secret half. The **secret** is never stored in the clear; the DB keeps only `HMAC-SHA256(secret, pepper)` or plain `SHA-256(secret)` when no pepper is configured.

**Why fast SHA-256 and not Argon2?** API keys are random 256-bit values. Argon2 / bcrypt / scrypt slow down brute force on **low-entropy** passwords. A 256-bit random secret has no brute-force attack to slow — a fast hash is correct here.

## Quick start

```js
import { createApiKey, verifyApiKey, revokeApiKey } from '@exortek/apikey';
import { memoryStore } from '@exortek/apikey/stores';

const store = memoryStore();
const peppers = [Buffer.from(process.env.APIKEY_PEPPER, 'base64url')]; // optional

// Issue a key to a user
const { key, id, record } = await createApiKey({
  store,
  peppers,
  prefix: 'sk_live',
  userId: 'usr_123',
  scopes: ['read', 'write:posts'],
  name: 'Production Backend',
  environment: 'live',
  expiresIn: '1y',
});
// → key = 'sk_live_A2X4…6QM' — SHOW ONCE, never persist in the clear.
// → id  = 'A2X4KJRK5HYFR3E7CBEQZP9WTN' — safe to log/display; primary key.

// Verify one on an incoming request
const res = await verifyApiKey(incomingKey, {
  store,
  peppers,
  requiredScopes: ['read'],
  updateLastUsed: true,
});
if (!res.valid) return reply.code(401).send({ error: res.reason });
// res = { valid: true, userId, scopes, id, prefix, name?, environment?, metadata?, needsRehash? }

// Revoke — by full key or by id
await revokeApiKey(incomingKey, { store, reason: 'user_dashboard' });
```

## API

### `createApiKey(options)`

```ts
createApiKey({
  store:        ApiKeyStore,
  prefix:       string,              // Stripe-style — see /^[a-z][a-z0-9]{0,15}(_[a-z0-9]{1,15}){0,3}$/
  userId:       string,
  scopes:       string[],

  name?:        string,              // Human label — 'Production Backend'
  environment?: string,              // 'live' / 'test' / caller-defined
  metadata?:    Record<string, unknown>,
  expiresIn?:   string | number,     // '1y' / '30d' / ms integer; omit for no expiry

  peppers?:     (Buffer | Uint8Array | string)[],  // Newest first, each ≥16 bytes
  now?:         number,              // Override Date.now() for testing
}): Promise<{ key: string, id: string, record: ApiKeyRecord }>
```

The wire `key` is returned once. Show it to the end user immediately (a dashboard modal, an email attachment) and never persist the raw value — only `record.hash` is safe to keep.

### `verifyApiKey(rawKey, options)`

```ts
verifyApiKey(rawKey, {
  store:            ApiKeyStore,
  peppers?:         (Buffer | Uint8Array | string)[],
  requiredScopes?:  string[],
  expectedPrefix?:  string,
  updateLastUsed?:  boolean,
  now?:             number,
}): Promise<
  | { valid: true, id, userId, scopes, prefix, name?, environment?, metadata?, needsRehash? }
  | { valid: false, reason }
>
```

Never throws on a bad key. Failure reasons:

| Reason              | Meaning                                                   |
| ------------------- | --------------------------------------------------------- |
| `malformed`         | Wrong shape, wrong length, non-crockford chars.           |
| `not_found`         | Well-shaped but the id has never been issued (or was purged). |
| `expired`           | `expiresAt` has passed.                                   |
| `revoked`           | Record has a `revokedAt` timestamp.                       |
| `bad_secret`        | HMAC compare failed — wrong secret or wrong pepper.       |
| `prefix_mismatch`   | `expectedPrefix` set and doesn't match; or the record's stored prefix differs from what was submitted (attacker guessed the id and swapped the prefix). |
| `missing_scope`     | `requiredScopes` not covered by the record's `scopes`.    |
| `store_unavailable` | `store.getById` threw.                                    |

### Scopes: `covers` / `hasAll` / `hasAny`

```js
import { covers, hasAll, hasAny } from '@exortek/apikey';

covers(['read:*'], 'read:users');           // true — namespace wildcard
covers(['*'], 'anything');                  // true — super wildcard
hasAll(['read:*'], ['read:users', 'read:posts']);   // true
hasAll(['read:users'], ['read:*']);         // false — required is more specific than granted
hasAny(['read'], ['read', 'write']);        // true
```

Wildcards only apply on the **granted** side. `required` values are always concrete — an endpoint declares exactly which scope it needs.

### Pepper rotation

```js
const oldPepper = Buffer.from(process.env.APIKEY_PEPPER_V1, 'base64url');
const newPepper = Buffer.from(process.env.APIKEY_PEPPER_V2, 'base64url');

// Verify against both, mint with the newest.
const res = await verifyApiKey(key, { store, peppers: [newPepper, oldPepper] });
if (res.valid && res.needsRehash) {
  await rehashApiKey(key, { store, peppers: [newPepper, oldPepper] });
}
```

Rotate a pepper by prepending the new one and keeping the old until every key has drifted to the new hash (either via `rehashApiKey` on natural verifies or via a batch job on a maintenance window). Then drop the old pepper.

### `mask(key)` / `parseApiKey(key)`

```js
import { mask, parseApiKey } from '@exortek/apikey';

mask('sk_live_A2X4KJRK…_QM5K…6QM');
// → 'sk_live_A2X4KJ…6QM' — log-safe

parseApiKey('sk_live_A2X4…_QM5…');
// → { prefix: 'sk_live', id: 'A2X4…', secret: 'QM5…' } — UNVERIFIED; do not trust
```

## Middleware

### Express

```js
import express from 'express';
import { apiKeyMiddleware } from '@exortek/apikey/middleware/express';
import { memoryStore } from '@exortek/apikey/stores';

const app = express();
const store = memoryStore();

app.use('/v1', apiKeyMiddleware({
  store,
  requiredScopes: ['read'],
  updateLastUsed: true,
}));

app.get('/v1/whoami', (req, res) => res.json(req.apiKey));
```

### Fastify

```js
import Fastify from 'fastify';
import { apiKeyPlugin } from '@exortek/apikey/middleware/fastify';
import { memoryStore } from '@exortek/apikey/stores';

const app = Fastify();
await app.register(apiKeyPlugin, {
  store: memoryStore(),
  requiredScopes: ['read'],
  updateLastUsed: true,
});

app.get('/v1/whoami', async req => req.apiKey);
```

### Options common to both

| Option              | Default             | Notes |
| ------------------- | ------------------- | ----- |
| `store`             | —                   | Required. |
| `peppers`           | none                | Newest-first array. |
| `requiredScopes`    | none                | Union with the endpoint's own scope checks. |
| `expectedPrefix`    | any                 | Reject a valid key whose prefix differs (e.g. lock a route to `sk_live`). |
| `updateLastUsed`    | `false`             | One extra store write per verify. |
| `headerName`        | `'authorization'`   | Case-insensitive. |
| `scheme`            | `'bearer'`          | `'bearer'` → `Bearer <key>`; `'raw'` → header value as-is (useful for `X-API-Key`). |
| `allowQueryParam`   | `false`             | Fall back to `?api_key=<key>` — discouraged (query strings leak into logs). |
| `queryParamName`    | `'api_key'`         | |
| `attach`            | `'apiKey'`          | `req[attach] = { valid, userId, scopes, … }`. |
| `tokenFromRequest`  | none                | Override extraction entirely. |

Invalid keys respond with 401 `{ error: 'invalid_api_key', reason }`; missing scope responds 403; store failure responds 503.

## Stores

`@exortek/apikey/stores` ships two implementations. Any object matching the `ApiKeyStore` interface works — bring your own if you already have a keys table in your DB.

- **`memoryStore()`** — in-process Map with a reverse index by `userId`. Not cluster-safe. Fine for dev / single-node prod / tests.
- **`redisStore(client, { keyPrefix? })`** — layout: `<keyPrefix><id>` (JSON blob) + `<keyPrefix>u:<userId>` (SADD-set of ids). Cluster-safe. Works with `ioredis`, `node-redis@4+`, `@upstash/redis`.

### The interface

```ts
interface ApiKeyStore {
  put(record: ApiKeyRecord): Promise<void>;
  getById(id: string): Promise<ApiKeyRecord | null>;
  update(id: string, patch: Partial<ApiKeyRecord>): Promise<ApiKeyRecord | null>;
  revoke(id: string, reason?: string): Promise<boolean>;
  revokeAllForUser(userId: string, reason?: string): Promise<number>;
  listByUser(userId: string): Promise<ApiKeyRecord[]>;
}
```

`ApiKeyRecord` fields: `id`, `hash`, `prefix`, `userId`, `scopes`, `createdAt`, `expiresAt?`, `revokedAt?`, `revokedReason?`, `lastUsedAt?`, `name?`, `environment?`, `metadata?`, `pepperVersion?`.

## Errors

```js
import { ApiKeyError, ErrorCode } from '@exortek/apikey';
```

| Code                | HTTP | Raised when |
| ------------------- | ---- | ----------- |
| `INVALID_ARGUMENT`  | 400  | Options object is missing, misshapen, or violates an invariant. |
| `INVALID_PREFIX`    | 400  | Prefix doesn't match the Stripe-style grammar. |
| `INVALID_PEPPER`    | 400  | Pepper is missing / under 16 bytes / wrong type. |
| `STORE_ERROR`       | 500  | `store.put` threw at create time (unusual — usually a DB outage). |

Expected verify failures do NOT throw — they surface as `{ valid: false, reason }`. See the failure-reasons table above.

## License

MIT
