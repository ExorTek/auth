# @exortek/jws

> JSON Web Signature for Node.js 22+ — **RFC 7515** (JWS core), **RFC 7518 §3** (JWA), **RFC 7797** (unencoded payload), **RFC 8037** (Ed25519 / Ed448), **RFC 8812** (`secp256k1`), **RFC 8725** (BCP). Zero-dependency, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/jws.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jws)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/jws.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/jws)](https://packagephobia.com/result?p=@exortek/jws)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/jws.svg?color=blue)](./LICENSE)

Sign and verify JWS in compact + JSON serialisation, with detached content
(RFC 7515 Appendix F) and unencoded payloads (RFC 7797). Covers HMAC / RSA /
RSA-PSS / ECDSA / EdDSA — including secp256k1 for Web3 interop. Five modern
guarantees `jose` does not enforce out of the box.

📖 **Docs:** [**auth.memet.dev/jws**](https://auth.memet.dev/jws)

## Why

`jose` is the reference JOSE library, but its verify contract makes it possible
to leave the algorithm allowlist off by mistake — the #1 way JWT authenticators
have been bypassed for a decade. The other JOSE libraries in the Node
ecosystem either predate modern secure defaults (`jsonwebtoken`) or focus on
JWT only (`fast-jwt`). This package sits deliberately in the JWS layer, is
server-only, has zero runtime dependencies, and enforces:

- **Mandatory `alg` allowlist on `verify`.** Omitting `options.alg` raises
  `MISSING_ALG_ALLOWLIST`. No default. No fallback.
- **`alg: 'none'` refused everywhere.** No flag, no environment variable, no
  configuration. Dedicated `ALGORITHM_NONE_FORBIDDEN` code. Refused at three
  layers: the sign / verify fast-path, the algorithm registry (no `none`
  entry), and the JSON serialisation surface.
- **`crit` strict by default.** Unknown critical headers raise
  `CRIT_UNSUPPORTED`. Opt in with `knownCriticalHeaders`.
- **Async key resolver is first-class.** `verify(token, async header => key,
  { alg: [...] })` is a plain function — no class dance.
- **Granular `ErrorCode` enum.** 13 machine-branchable codes.
  `switch (err.code)` beats string-matching on `err.message`.

## Install

```bash
npm  install @exortek/jws
yarn add     @exortek/jws
pnpm add     @exortek/jws
```

Requires **Node.js 22 or newer**. Zero runtime dependencies.

## Quick start

```js
import { sign, verify } from '@exortek/jws'
import { generateKeyPairSync } from 'node:crypto'

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })

const token = await sign(
  { userId: 1, role: 'admin' },
  privateKey,
  { alg: 'ES256', kid: 'signing-key-2026' },
)

const { header, payload, kid } = await verify(token, publicKey, {
  alg: ['ES256'],   // <-- MANDATORY. Not optional.
})
```

Multi-key verification with automatic `kid` dispatch:

```js
const jwks = [
  { kty: 'EC', crv: 'P-256', x: '…', y: '…', kid: 'k1' },
  { kty: 'EC', crv: 'P-256', x: '…', y: '…', kid: 'k2' },
]
await verify(token, jwks, { alg: ['ES256'] })
```

Async key resolver — kid-driven store lookup:

```js
await verify(token, async header => store.get(header.kid), { alg: ['ES256'] })
```

Detached content (RFC 7515 §F):

```js
import { signDetached, verifyDetached } from '@exortek/jws'

const { token, detached } = await signDetached(bigUploadBuffer, key, { alg: 'ES256' })
// token.split('.')[1] === '' — payload segment is empty.
await verifyDetached(token, detached, publicKey, { alg: ['ES256'] })
```

Unencoded payload (RFC 7797):

```js
await sign('opaque protocol frame', secret, { alg: 'HS256', b64: false })
// header.b64 = false, crit = ['b64'] auto-added.
```

Detached + unencoded together — canonical form for `x-jws-signature` (Open
Banking) and JAdES:

```js
const { token, detached } = await signDetached(payloadBuf, key, {
  alg: 'ES256',
  b64: false,
})
await verifyDetached(token, detached, publicKey, { alg: ['ES256'] })
// b64:false detached tolerates '.' in the payload — no compact-form ambiguity.
```

JSON serialisation with multiple signers:

```js
import { signJson, verifyJson } from '@exortek/jws'

const jws = await signJson({ claim: 'x' }, [
  { key: hmacSecret, options: { alg: 'HS256', kid: 'hs1' } },
  { key: rsaPrivateKey, options: { alg: 'RS256', kid: 'rs1' } },
])
// Two signers → general form: { payload, signatures: [...] }

const { matchedSignatureIndex } = await verifyJson(jws, jwks, {
  alg: ['HS256', 'RS256'],
})
```

## Modules

| Subpath                                | Purpose                                                                                     |
| -------------------------------------- | ------------------------------------------------------------------------------------------- |
| [`@exortek/jws/sign`](./src/sign.js)   | `sign`, `signDetached` — compact serialisation, with `b64: false` and detached options       |
| [`@exortek/jws/verify`](./src/verify.js) | `verify`, `verifyDetached` — mandatory allowlist, polymorphic key input, kid dispatch        |
| [`@exortek/jws/decode`](./src/decode.js) | `decode`, `decodeProtectedHeader` — **UNSAFE** inspection helpers                            |
| [`@exortek/jws/json`](./src/json.js)   | `signJson`, `verifyJson` — general (multi-signature) + flattened JSON serialisation          |

## Import styles

```js
// 1. Namespace — mirrors the ARCHITECTURE example.
import { jws } from '@exortek/jws'
await jws.sign(payload, key, { alg: 'ES256' })

// 2. Named — smallest bundle, tree-shakeable.
import { sign, verify, signJson, verifyJson } from '@exortek/jws'

// 3. Subpath — one concern at a time.
import { sign }             from '@exortek/jws/sign'
import { verify }           from '@exortek/jws/verify'
import { decode }           from '@exortek/jws/decode'
import { signJson }         from '@exortek/jws/json'
```

## Error handling

Every recoverable failure throws `JwsError` with a stable `ErrorCode`. Branch
on the code, never on the message.

```js
import { JwsError, ErrorCode } from '@exortek/jws'

try {
  await verify(token, key, { alg: ['ES256'] })
} catch (err) {
  if (!(err instanceof JwsError)) throw err
  switch (err.code) {
    case ErrorCode.MISSING_ALG_ALLOWLIST:    /* config bug — allowlist required */ break
    case ErrorCode.ALGORITHM_MISMATCH:       /* token alg outside allowlist */    break
    case ErrorCode.ALGORITHM_NONE_FORBIDDEN: /* refused unconditionally */         break
    case ErrorCode.INVALID_SIGNATURE:        /* tampered token */                  break
    case ErrorCode.INVALID_KEY:              /* alg-confusion / wrong kty */       break
    case ErrorCode.KEY_NOT_FOUND:            /* resolver had no matching kid */    break
    case ErrorCode.TOKEN_TOO_LARGE:          /* DoS guard tripped */               break
    case ErrorCode.CRIT_UNSUPPORTED:         /* unknown critical header */         break
    // …
  }
}
```

All codes: `INVALID_ARGUMENT`, `INVALID_TOKEN`, `INVALID_HEADER`,
`INVALID_PAYLOAD`, `INVALID_SIGNATURE`, `INVALID_KEY`, `UNSUPPORTED_ALGORITHM`,
`ALGORITHM_MISMATCH`, `ALGORITHM_NONE_FORBIDDEN`, `MISSING_ALG_ALLOWLIST`,
`CRIT_UNSUPPORTED`, `KEY_NOT_FOUND`, `TOKEN_TOO_LARGE`.

## Post-quantum roadmap

**ML-DSA** (FIPS 204 signatures) and **ML-KEM** (FIPS 203 key encapsulation)
are on the roadmap for the JOSE stack. Shipping today would mean bundling
a JavaScript implementation of NIST-selected lattice cryptography — a red
line. The path forward is `node:crypto` native support:

- OpenSSL added ML-DSA / ML-KEM in **3.5** (April 2025).
- Node.js 22–24 ships OpenSSL 3.0–3.4 — no native PQ yet.
- Node.js 25 / 26 (2026–2027) will expose them once the OpenSSL bump lands.
- `draft-ietf-jose-pqc` (JOSE registrations) is still a draft.

When both boxes tick we add `alg: 'ML-DSA-{44,65,87}'` to the same
`sign` / `verify` surface. Until then, `@noble/post-quantum` is the
credible JS alternative you can plug into your own code path.

## Highlights

- **RFC 7515 Appendix A test vectors pinned.** A.1 (HS256), A.2 (RS256),
  A.3 (ES256), A.4 (ES512) verify verbatim from the spec's example JWKs
  and token strings — cross-vendor interop guard.
- **Algorithm confusion (CVE-2015-9235)** is caught at the key boundary
  with `INVALID_KEY` regardless of whether you pass a `KeyObject`, a JWK,
  or a `Buffer`.
- **ECDSA signatures are RFC 7515 §3.4 raw R‖S** — Node produces ASN.1 DER,
  we convert both directions. P-256, P-384, P-521, and secp256k1 coordinates
  are padded per the spec.
- **HMAC verification is timing-safe.** `crypto.timingSafeEqual` on
  equal-length digest buffers.
- **HMAC secret length enforced (RFC 7518 §3.2).** HS256 ≥ 32 B,
  HS384 ≥ 48 B, HS512 ≥ 64 B — short secrets raise `INVALID_KEY` at the
  sign call, never quietly downgraded.
- **RSA modulus length enforced (RFC 7518 §3.3 / §3.5).** RS/PS keys
  under 2048 bits are refused with `INVALID_KEY`, matching the HMAC
  policy above.
- **`crit` and `b64` handled correctly.** `b64: false` auto-injects `crit:
  ['b64']` per RFC 7797 §5.1; unknown critical params refuse; `crit`
  cannot list itself. `detached + b64:false` fully supported for
  `x-jws-signature` / JAdES interop.
- **`maxTokenSize` DoS guard** — default 8 KB, configurable per call.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
