# @exortek/jwt

> JSON Web Token for Node.js 22+ — **RFC 7519** (JWT core) + **RFC 8725** (BCP) + **RFC 9068** (OAuth 2.0 profile). Zero-dependency, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/jwt.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jwt)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/jwt.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/jwt)](https://packagephobia.com/result?p=@exortek/jwt)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/jwt.svg?color=blue)](./LICENSE)

Sign and verify JSON Web Tokens with the algorithm matrix `jose`
supports (HS/RS/PS/ES/EdDSA + secp256k1) plus twelve differentiators
you don't get from `jsonwebtoken` / `jose` / `fast-jwt` — headlined by
**`tokenPair` with reuse detection**, the RFC 6749 §10.4 pattern every
production JWT flow reinvents by hand.

📖 **Docs:** [**auth.memet.dev/jwt**](https://auth.memet.dev/jwt)

## Why

The JWT space has three big libraries and each leaves gaps:

- **`jsonwebtoken`** — 30M downloads/week, callback-first, algorithm
  allowlist is *optional* (`algorithms: ['HS256']` easy to forget →
  #1 CVE class of the past decade), no built-in refresh / rotation /
  revocation.
- **`jose`** — modern and runtime-agnostic; that runtime-agnosticism
  brings ~100 modules of bloat, verbose `SignJWT` class ceremony, and
  still no token pair / blacklist / middleware.
- **`fast-jwt`** — speed-focused; minimal claims validation, no
  rotation / revocation.

`@exortek/jwt` is server-only, zero-dep, and refuses to let the caller
opt out of the checks that matter.

## The twelve differentiators

1. **`tokenPair` with reuse detection.** Refresh rotation, RFC 6749
   §10.4 — reuse detected → the whole family is revoked with
   `REFRESH_REUSED`. No other lib ships this.
2. **Mandatory `alg` allowlist on verify.** Omission raises
   `MISSING_ALG_ALLOWLIST`.
3. **`alg: 'none'` refused everywhere.** No flag can enable it.
4. **Blacklist store** — memory + Redis + custom, with 3 GC strategies.
5. **Custom-fn escape hatch on every knob** — `hashFn`, `generate`,
   `issuer` / `audience` predicates, encoding.
6. **`typ` enforcement** with `at+jwt` allowlisting (RFC 9068).
7. **`maxAge` — iat freshness policy** for leaked-token mitigation.
8. **`scope` validation first-class** (`requiredScopes: ['read:users']`).
9. **`peek`** — signature-verified inspection without claim checks.
10. **`sign` metadata return** — `{ token, jti, expiresAt, issuedAt, alg, kid }`.
11. **`aud` array + `iss` array on verify** — multi-tenant native.
12. **PEM string + X.509 certificate input** — `fs.readFileSync` friendly.

## Install

```bash
npm install @exortek/jwt
```

Optional Redis peer deps only if you use the Redis store:

```bash
npm install ioredis      # or:
npm install redis
```

Requires **Node.js 22 or newer**.

## Quick start

```js
import { sign, verify } from '@exortek/jwt'
import { randomBytes } from 'node:crypto'

const secret = randomBytes(32)

const token = await sign(
  { userId: 1, role: 'admin' },
  secret,
  { alg: 'HS256', expiresIn: '15m', issuer: 'api.myapp.com' },
)

const { header, payload } = await verify(token, secret, {
  alg: ['HS256'],
  issuer: 'api.myapp.com',
  clockTolerance: '10s',
})
```

PEM / X.509 cert input (`fs.readFileSync` friendly):

```js
import { readFileSync } from 'node:fs'
const priv = readFileSync('./private.pem', 'utf8')
const pub  = readFileSync('./public.pem',  'utf8')     // or a .crt X.509 file

const token = await sign(payload, priv, { alg: 'RS256' })
await verify(token, pub, { alg: ['RS256'] })
```

Async key resolver (kid-based JWKS lookup):

```js
await verify(token, async header => jwksStore.get(header.kid), {
  alg: ['ES256'],
})
```

`peek` for audit paths that need identity even from expired tokens:

```js
const { payload } = await peek(token, key, { alg: ['ES256'] })
logger.info({ userId: payload.userId })   // signature-verified, claim checks skipped
```

## Token pair (refresh + reuse detection)

```js
import { tokenPair } from '@exortek/jwt/token-pair'
import { createStore } from '@exortek/jwt/stores'

const store = createStore('memory', { gc: { strategy: 'interval' } })

const { accessToken, refreshToken, familyId } = await tokenPair.create(
  { userId: 1, sub: 'user-1' },
  {
    secret: { access: accessSecret, refresh: refreshSecret },
    access:  { alg: 'ES256', expiresIn: '15m' },
    refresh: { expiresIn: '7d', store },  // opaque by default — random bytes, no alg needed
  },
)

// On refresh:
try {
  const next = await tokenPair.rotate(refreshToken, {
    secret: { access: accessSecret, refresh: refreshSecret },
    access:  { alg: 'ES256', expiresIn: '15m' },
    refresh: { expiresIn: '7d', store },
    detectReuse: true,          // default
    reuseWindow: 5,             // seconds grace for network races
  })
} catch (err) {
  if (err.code === 'REFRESH_REUSED') {
    // Family was revoked — force re-login.
  }
}

// Explicit revocation:
await tokenPair.revoke(refreshToken, { store })
await tokenPair.revokeAll(familyId,   { store })
```

## Modules

| Subpath                                                | Purpose                                                                                       |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| [`@exortek/jwt`](https://github.com/ExorTek/auth/blob/master/packages/jwt/src/index.js)             | `sign`, `verify`, `peek`, `decode`, `decodeProtectedHeader`                                    |
| [`@exortek/jwt/token-pair`](https://github.com/ExorTek/auth/blob/master/packages/jwt/src/token-pair.js) | `tokenPair.create / .rotate / .revoke / .revokeAll` with RFC 6749 §10.4 reuse detection       |
| [`@exortek/jwt/stores`](https://github.com/ExorTek/auth/blob/master/packages/jwt/src/stores.js)     | `createStore('memory' \| 'redis' \| 'custom', ...)` with interval / lazy / lru GC strategies  |

## Error handling

Every failure throws `JwtError` with a stable `ErrorCode`. Branch on
`code`, never on the message.

```js
import { JwtError, ErrorCode } from '@exortek/jwt'

try {
  await verify(token, key, { alg: ['ES256'] })
} catch (err) {
  if (!(err instanceof JwtError)) throw err
  switch (err.code) {
    case ErrorCode.MISSING_ALG_ALLOWLIST:    /* forgot options.alg — config bug */    break
    case ErrorCode.ALGORITHM_NONE_FORBIDDEN: /* attacker sent alg:none */              break
    case ErrorCode.TOKEN_EXPIRED:            /* refresh or reject */                   break
    case ErrorCode.TOKEN_TOO_OLD:            /* maxAge tripped */                      break
    case ErrorCode.INVALID_SIGNATURE:        /* tampered */                            break
    case ErrorCode.INVALID_KEY:              /* alg confusion / short secret */        break
    case ErrorCode.INVALID_AUDIENCE:         /* aud mismatch */                        break
    case ErrorCode.REFRESH_REUSED:           /* family revoked — force login */        break
    // …
  }
}
```

All codes: `INVALID_ARGUMENT`, `INVALID_TOKEN`, `INVALID_HEADER`,
`INVALID_PAYLOAD`, `INVALID_SIGNATURE`, `INVALID_KEY`,
`UNSUPPORTED_ALGORITHM`, `ALGORITHM_MISMATCH`,
`ALGORITHM_NONE_FORBIDDEN`, `MISSING_ALG_ALLOWLIST`, `TOKEN_EXPIRED`,
`TOKEN_NOT_YET_VALID`, `TOKEN_TOO_OLD`, `TOKEN_TOO_LARGE`,
`INVALID_ISSUER`, `INVALID_AUDIENCE`, `INVALID_SUBJECT`,
`INVALID_NONCE`, `INVALID_TYP`, `INSUFFICIENT_SCOPE`, `MISSING_CLAIM`,
`CRIT_UNSUPPORTED`, `KEY_NOT_FOUND`, `REFRESH_REUSED`, `REVOKED`,
`STORE_ERROR`.

## Why not

Deliberate omissions — these will **not** be added:

- `alg: 'none'` (any flag path)
- Callback-style API (Promise-only; Node 22+)
- Synchronous `sign` / `verify`
- `ignoreExpiration` / `ignoreNotBefore` (`peek` is the safe alternative)
- `mutatePayload` (payload is always immutable)
- `allowInsecureKeySizes` / `allowInvalidAsymmetricKeyTypes` (footguns)
- `zip: 'DEF'` compression (fringe use, unlocks decompression bombs)
- `x5u` URL fetch (SSRF surface)
- SHA-1 based algorithms

## v1.1 roadmap

Framework middleware (fastify/express), `bindTo` fingerprint
binding, `extractBearer` helper, secret rotation manager, nested JWT
(JWS + JWE), introspection helper (RFC 7662), DPoP (RFC 9449), JAR
(RFC 9101), OpenTelemetry hooks, MongoDB + SQLite store adapters,
`x5c` / `x5t` header handling.

## Post-quantum

ML-DSA (FIPS 204) / ML-KEM (FIPS 203) will land when `node:crypto`
exposes them natively (Node 25/26 + `draft-ietf-jose-pqc` finalisation).
Until then, `@noble/post-quantum` is the credible JS alternative you
plug into your own code path.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](https://github.com/ExorTek/auth/blob/master/packages/jwt/CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
