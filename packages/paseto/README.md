# @exortek/paseto

> Platform-Agnostic Security Tokens (**PASETO v4**) for Node.js 22+ — `v4.local` (XChaCha20 + keyed BLAKE2b) + `v4.public` (Ed25519). Zero-dependency, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/paseto.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/paseto)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/paseto.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/paseto)](https://packagephobia.com/result?p=@exortek/paseto)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![zero-deps](https://img.shields.io/badge/dependencies-0-brightgreen)](./package.json)
[![license](https://img.shields.io/npm/l/@exortek/paseto.svg?color=blue)](https://github.com/ExorTek/auth/blob/master/LICENSE)

A safer, non-negotiable-primitive alternative to JWT. A PASETO token's
`vN.purpose.` prefix binds the exact primitive set — there is no
`alg` header to tamper with — so the algorithm-confusion attacks
(`alg: none`, RS256↔HS256) that headline the JWT CVE list are
**structurally impossible**. Server-only, zero-dep, verified byte-for-byte
against the official PASETO v4 test vectors.

📖 **Docs:** [**auth.memet.dev/paseto**](https://auth.memet.dev/paseto)

| Version     | Purpose | Primitive                                 | Use                    |
| ----------- | ------- | ----------------------------------------- | ---------------------- |
| `v4.local`  | encrypt | XChaCha20 + keyed BLAKE2b (encrypt-then-MAC) | recommended — internal |
| `v4.public` | sign    | Ed25519                                   | recommended — external |

## Why

PASETO fixes JWT's original sins, but the existing JS options leave gaps:

- **`jsonwebtoken` / `jose` / `fast-jwt`** — JWT, and JWT carries a
  negotiable `alg` header. The allowlist is opt-in; forgetting it is
  the #1 CVE class of the past decade.
- **`paseto` (reference JS lib)** — correct but low-level: you hand it
  strings, wire up claim validation yourself, and there is no token
  pair / rotation / store.

`@exortek/paseto` ships the primitive **and** the high-level flow every
production login reinvents:

1. **No `alg` header, ever.** The version dictates the primitive —
   confusion attacks cannot be expressed.
2. **`v4.local` = encrypted tokens.** Confidential payloads, not just
   authenticated — the JWE role without the JWE footgun matrix.
3. **`tokenPair` with reuse detection.** Access + refresh, RFC 6749
   §10.4 — a replayed refresh revokes the whole family with
   `REFRESH_REUSED`.
4. **Refresh store** — memory + Redis + custom, with GC strategies.
5. **Claim ergonomics** — ISO 8601 `exp` / `nbf` / `iat`, `iss` /
   `sub` / `aud`, `clockTolerance`, all validated for you.
6. **Caller picks the access purpose** — `local` (encrypted) or
   `public` (signed), same API.
7. **Zero runtime dependencies.** Keyed BLAKE2b and HChaCha20 are
   vendored because `node:crypto` doesn't expose them; nothing is
   pulled from npm.

## Install

```bash
npm install @exortek/paseto
```

Optional Redis peer deps only if you use the Redis store:

```bash
npm install ioredis      # or:
npm install redis
```

Requires **Node.js 22 or newer**.

## Quick start

### `v4.local` — symmetric (encrypted)

For tokens your own services both mint and read.

```js
import { generateKey, encrypt, decrypt } from '@exortek/paseto';

const key = generateKey(); // 32-byte symmetric key

const token = encrypt({ userId: 1, role: 'admin' }, key, {
  expiresIn: '1h',
  issuer: 'api.myapp.com',
});

const data = decrypt(token, key, {
  issuer: 'api.myapp.com',
  clockTolerance: '10s',
});
// → { userId: 1, role: 'admin', iat: '…', exp: '…', iss: 'api.myapp.com' }
```

### `v4.public` — asymmetric (signed)

When a relying party other than the issuer must verify the token.

```js
import { generateKeyPair, sign, verify } from '@exortek/paseto';

const { secretKey, publicKey } = generateKeyPair();

const token = sign({ userId: 1 }, secretKey, { expiresIn: '1h' });
const payload = verify(token, publicKey);
```

Footers and implicit assertions are authenticated; `complete: true`
returns `{ payload, footer, version, purpose }`:

```js
const token = sign(payload, secretKey, { footer: { kid: 'key-2026' } });
const { footer } = verify(token, publicKey, { complete: true });
```

### Reading the footer before verifying (`kid` selection)

`decode` reads a token's `version` / `purpose` / `footer` **without a
key and without authenticating anything** — the footer is designed for
exactly this, picking a key by `kid` before you call `verify`. It never
returns the payload (encrypted for `v4.local`, unverified for
`v4.public`), so you can't accidentally trust it.

```js
import { decode } from '@exortek/paseto';

const { purpose, footer } = decode(token); // no key
const key = keyring.get(footer.kid);
const payload = verify(token, key);
```

Decoders reject a token larger than `maxTokenSize` (default 8192 bytes,
`TOKEN_TOO_LARGE`) before doing any base64 / crypto work.

## Token pair (refresh + reuse detection)

```js
import { create, rotate, revoke, revokeAll } from '@exortek/paseto/token-pair';
import { createStore } from '@exortek/paseto/stores';
import { generateKey } from '@exortek/paseto';

const store = createStore('memory', { gc: { strategy: 'interval' } });

const { accessToken, refreshToken, familyId } = await create(
  { userId: 1 },
  {
    secret: { access: generateKey() },
    access: { expiresIn: '15m' }, // purpose: 'public' → signed access tokens
    refresh: { expiresIn: '7d', store }, // opaque by default — random bytes
  },
);

// On refresh:
try {
  const next = await rotate(refreshToken, {
    secret: { access: generateKey() },
    access: { expiresIn: '15m' },
    refresh: { expiresIn: '7d', store },
    reuseWindow: 5, // seconds grace for network races
  });
} catch (err) {
  if (err.code === 'REFRESH_REUSED') {
    // Family was revoked — force re-login.
  }
}

await revoke(refreshToken, { store });
await revokeAll(familyId, { store });
```

## Modules

| Subpath                                                                                                      | Purpose                                                                                          |
| ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| [`@exortek/paseto`](https://github.com/ExorTek/auth/blob/master/packages/paseto/src/index.js)               | `encrypt`, `decrypt`, `sign`, `verify`, `decode`, `generateKey`, `generateKeyPair`               |
| [`@exortek/paseto/token-pair`](https://github.com/ExorTek/auth/blob/master/packages/paseto/src/token-pair.js) | `create` / `rotate` / `revoke` / `revokeAll` with RFC 6749 §10.4 reuse detection                |
| [`@exortek/paseto/stores`](https://github.com/ExorTek/auth/blob/master/packages/paseto/src/stores.js)       | `createStore('memory' \| 'redis' \| 'custom', ...)` with interval / lazy / lru GC strategies    |

## Error handling

Every failure throws `PasetoError` with a stable `ErrorCode`. Branch on
`code`, never on the message.

```js
import { PasetoError, ErrorCode } from '@exortek/paseto';

try {
  const data = decrypt(token, key);
} catch (err) {
  if (!(err instanceof PasetoError)) throw err;
  switch (err.code) {
    case ErrorCode.TOKEN_EXPIRED:      /* refresh or reject */          break;
    case ErrorCode.NOT_YET_VALID:      /* nbf in the future */          break;
    case ErrorCode.DECRYPTION_FAILED:  /* wrong key or tampered */      break;
    case ErrorCode.SIGNATURE_INVALID:  /* tampered v4.public */         break;
    case ErrorCode.CLAIM_MISMATCH:     /* iss / sub / aud mismatch */   break;
    case ErrorCode.INVALID_TOKEN:      /* malformed / wrong purpose */  break;
    case ErrorCode.REFRESH_REUSED:     /* family revoked — force login */ break;
    // …
  }
}
```

All codes: `INVALID_ARGUMENT`, `INVALID_TOKEN`, `INVALID_KEY`,
`UNSUPPORTED_VERSION`, `TOKEN_TOO_LARGE`, `DECRYPTION_FAILED`,
`SIGNATURE_INVALID`, `TOKEN_EXPIRED`, `NOT_YET_VALID`, `CLAIM_MISMATCH`,
`REVOKED`, `REFRESH_REUSED`, `STORE_ERROR`.

## Why not

Deliberate omissions — these will **not** be added:

- **PASETO v3 / v1 / v2** — v4 is the current recommended version; v3
  exists only for FIPS / legacy-curve constraints. Adding a version is
  purely additive (purpose is bound in the token), so it can land in a
  minor if there is real demand.
- Any negotiable `alg` header (the whole point of PASETO)
- Callback-style API (Promise-only; Node 22+)
- `ignoreExp` as a silent default (opt-in per call only)
- Local / non-CSPRNG nonces (nonces are always random)

## Post-quantum

ML-DSA (FIPS 204) / ML-KEM (FIPS 203) will land across the JOSE stack
when `node:crypto` exposes them natively. PASETO has no PQ version yet;
this package tracks the spec.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](https://github.com/ExorTek/auth/blob/master/packages/paseto/CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](https://github.com/ExorTek/auth/blob/master/LICENSE).
