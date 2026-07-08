# @exortek/crypto

> Zero-dependency cryptographic primitives for Node.js — built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/crypto.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/crypto)
[![tests](https://img.shields.io/badge/tests-448%20passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/crypto.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/crypto)](https://packagephobia.com/result?p=@exortek/crypto)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![zero-deps](https://img.shields.io/badge/dependencies-0-brightgreen)](./package.json)
[![license](https://img.shields.io/npm/l/@exortek/crypto.svg?color=blue)](./LICENSE)

Hash, HMAC, KDFs, authenticated encryption, asymmetric signatures,
timing-safe compare, sealed tokens, CSPRNG helpers, and encoders — all
built directly on `node:crypto`. No runtime dependencies, no polyfills,
pure ESM with a matching CJS output.

📖 **Docs:** [**auth.memet.dev**](https://auth.memet.dev/crypto)

## Why

Node's `crypto` module is powerful but full of foot-guns — nonce reuse, wrong
padding, non-timing-safe compares, incompatible signature encodings, inconsistent
option shapes. Every auth-adjacent codebase re-implements the same 30 helpers on
top of it, badly. `@exortek/crypto` ships them once, correctly:

- **Ergonomic by default.** `random.pin(6)` never returns `'000000'`.
  `hash.hmac(data, secret)` is timing-safe by construction. `cipher.seal(payload,
  secret, { ttl: '1h' })` mints a tamper-proof token you can put in a URL.
- **Framework-agnostic.** No Express, Fastify, Hono or Elysia coupling.
- **Zero deps.** `node:crypto` is the only runtime input. `dist` is a few
  kilobytes per subpath.
- **JSDoc → `.d.ts`.** Pure JavaScript source, TypeScript types emitted at build.
  IDE hints work without a `.ts` in sight.

## Install

```bash
npm  install @exortek/crypto
yarn add     @exortek/crypto
pnpm add     @exortek/crypto
```

Requires **Node.js 22 or newer**.

## Quick start

```js
import { random, hash, cipher, sign } from '@exortek/crypto'

// A 6-digit OTP that will never render '000000'
const otp = random.pin(6)

// A webhook signature you can safely compare in a handler
const ok = hash.verifyHmac(body, req.headers['x-signature'], WEBHOOK_SECRET)

// A cookie-safe encrypted, authenticated string
const key   = await cipher.generateKey()
const token = cipher.encryptToString(JSON.stringify({ userId: 42 }), key)

// A 1-hour password-reset ticket — payload is private, expiry is unforgeable
const ticket = cipher.seal({ userId: 42, purpose: 'pw-reset' }, RESET_SECRET, {
  ttl: '1h',
})

// A JOSE-standard signature with the JWK thumbprint as `kid`
const kp  = await sign.generateSignKeyPair('es256')
const sig = sign.sign('claim=1', kp.privateKey, { algo: 'es256' })
const kid = sign.thumbprint(kp.publicKey)
```

## Modules

Every module is available at the top level **and** via a subpath entry — pick
the subpath for the smallest tree-shaken bundle.

| Module | Purpose | Key exports |
| --- | --- | --- |
| [`random`](./src/random) | CSPRNG helpers | `bytes` · `hex` · `base64url` · `base58` · `crockford` · `alphanumeric` · `numeric` · `pin` · `code` · `serial` · `token` · `uuid4` / `uuid5` / `uuid7` · `ulid` |
| [`hash`](./src/hash) | digests, HMAC, KDFs | `hash` · `hmac` · `compare` (timing-safe) · `verifyHmac` · `pbkdf2` · `hkdf` · `scrypt` · `signValue` / `unsignValue` · `fingerprint` |
| [`cipher`](./src/cipher) | symmetric + asymmetric encryption | `generateKey` / `generateKeyPair` · `encryptSymmetric` / `decryptSymmetric` (AES-GCM/CBC, ChaCha20-Poly1305) · `encryptAsymmetric` / `decryptAsymmetric` (RSA-OAEP) · `encryptHybrid` · `deriveSharedSecret` (ECDH / X25519) · `encryptWithPassphrase` · `seal` / `unseal` |
| [`sign`](./src/sign) | asymmetric signatures | `sign` · `verify` · `generateSignKeyPair` · `thumbprint` — supports RS/PS/ES 256/384/512 and EdDSA |
| [`encode`](./src/encode) | codec pairs | `base64url` · `base64` · `base32` · `base58` · `crockford` · `hex` — each with `encode` / `decode` |
| [`binary`](./src/binary) | byte utilities | `concat` · `xor` · `wipe` · `equal` |
| errors | typed error surface | `CryptoError` + stable `ErrorCode` enum |

## Import styles

Three styles, all supported, all tree-shakable.

```js
// 1. Named at the top level — most ergonomic
import { hmac, cipher, uuid4, seal } from '@exortek/crypto'

// 2. Named from a subpath — smallest bundle
import { uuid4 }  from '@exortek/crypto/random'
import { hmac }   from '@exortek/crypto/hash'
import { seal }   from '@exortek/crypto/cipher'

// 3. Namespace — bulk / REPL / interactive
import { random, cipher } from '@exortek/crypto'
random.uuid4()
await cipher.generateKey()
```

## Error handling

Every entry point throws `CryptoError` with a stable, machine-readable `code`.
Branch on the code — never on the message.

```js
import { CryptoError, ErrorCode, cipher } from '@exortek/crypto'

try {
  const { payload } = cipher.unseal(req.query.t, RESET_SECRET)
  await resetPassword(payload.userId)
} catch (err) {
  if (!(err instanceof CryptoError)) throw err
  switch (err.code) {
    case ErrorCode.TOKEN_EXPIRED:   return res.render('expired')
    case ErrorCode.TOKEN_TAMPERED:  return res.status(404).end()
    case ErrorCode.TOKEN_MALFORMED: return res.status(400).end()
    default: throw err
  }
}
```

Codes currently emitted:

| Code | When |
| --- | --- |
| `INVALID_ARGUMENT` | Type / range / shape validation on a function argument. |
| `UNSUPPORTED_ALGORITHM` | Algorithm name not in the module's whitelist. |
| `INVALID_KEY` | `KeyObject` missing, wrong type, or unusable with the algorithm. |
| `INVALID_CIPHERTEXT` | Ciphertext blob is malformed (truncated, bad framing). |
| `DECRYPT_FAILED` | Authenticated decryption failed (wrong key, tag mismatch, tampered bytes). |
| `INVALID_ENCODING` | Encoded input has characters outside the target alphabet. |
| `TOKEN_MALFORMED` | Sealed token's structure/framing is unparseable. |
| `TOKEN_TAMPERED` | Sealed token failed authenticated decryption. |
| `TOKEN_EXPIRED` | Sealed token's TTL has passed. |

## Highlights

A few primitives that are hard to find elsewhere done well:

- **`hash.verifyHmac(body, expected, secret)`** — Stripe / GitHub / Slack /
  Twilio / Vercel all sign webhooks with HMAC-SHA-256. This is a one-line,
  timing-safe verify.
- **`hash.fingerprint(any)`** — canonical (RFC 8785) hash of any JSON-shaped
  value. Same content, different key order → same fingerprint. Use as a cache
  key, ETag, dedup key, idempotency key.
- **`hash.signValue(value, secret) / unsignValue`** — the Express
  `cookie-signature` / Django `signing` primitive. `<value>.<mac>`, timing-safe.
- **`cipher.seal(payload, secret, { ttl })`** — encrypted, authenticated,
  auto-expiring token. Payload is private (unlike a JWT), expiry is unforgeable.
  Password reset, email verification, magic-link tokens.
- **`sign.thumbprint(key)`** — the JWT `kid` value for any keypair, matching
  common JOSE conventions.
- **`random.pin(n)`, `random.code(n)`, `random.token(size, { prefix })`** —
  rejection-sampled uniform IDs. `pin(6)` never returns `'000000'`.
  `token(32, { prefix: 'sk_live' })` gives a Stripe-style secret.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues & discussions:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
