# @exortek/auth

> A framework-agnostic, zero-dependency authentication toolkit for Node.js.

[![license](https://img.shields.io/github/license/ExorTek/auth?color=blue)](./LICENSE)
[![CI](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/badge/node-%3E%3D22-339933)](https://nodejs.org)
[![docs](https://img.shields.io/badge/docs-auth.memet.dev-cb3837)](https://auth.memet.dev)

`@exortek/auth` is a monorepo of small, sharp packages that each solve one
piece of the auth problem correctly — and, together, replace the
`passport + jsonwebtoken + bcrypt + speakeasy + csurf + otplib + …` stack
most Node apps end up stitching together.

Every package is built directly on `node:crypto`. No runtime dependencies.
Pure JavaScript with JSDoc → `.d.ts`. Framework-agnostic — Express,
Fastify, Hono, Elysia.

## Shipping today

| Package | Purpose | Version |
| --- | --- | --- |
| [`@exortek/crypto`](./packages/crypto) | hash · hmac · KDFs · cipher · sign · seal · encode · CSPRNG | [![npm](https://img.shields.io/npm/v/@exortek/crypto.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/crypto) |

## The plan

Twenty-three packages, one scope. Numbering reflects dependency order
— a lower number never imports from a higher one, so you can adopt one
package at a time.

| # | Package | What it does |
| :---: | --- | --- |
| 01 | [`@exortek/crypto`](./packages/crypto) | hash, HMAC, KDFs, AEAD ciphers, asymmetric signatures, sealed tokens, CSPRNG, encoders |
| 02 | `@exortek/password` | Argon2id / bcrypt hashing, strength scoring, HIBP breach check |
| 03 | `@exortek/otp` | TOTP / HOTP, backup codes, QR provisioning URI |
| 04 | `@exortek/challenge` | e-mail / SMS one-time code storage + verification |
| 05 | `@exortek/jwk` | JWK ↔ PEM ↔ DER converters, key rotation helpers |
| 06 | `@exortek/jws` | JOSE-standard signed payloads (compact + JSON) |
| 07 | `@exortek/jwt` | JWT sign / verify with algorithm allowlists and clock skew |
| 08 | `@exortek/jwe` | JWE encrypted payloads (RSA-OAEP, A256KW, dir) |
| 09 | `@exortek/jwks` | JWKS URI fetching, caching, `kid` rotation |
| 10 | `@exortek/session` | signed cookies, rotation, revocation, store adapter |
| 11 | `@exortek/csrf` | double-submit + signed origin-bound tokens |
| 12 | `@exortek/rate-limit` | token bucket, sliding window, per-IP / per-user |
| 13 | `@exortek/device` | device fingerprinting, trusted-device tokens |
| 14 | `@exortek/apikey` | prefixed API keys (`sk_live_...`), rate-limited by default |
| 15 | `@exortek/magic-link` | passwordless email + SMS link tokens |
| 16 | `@exortek/passkey` | WebAuthn / FIDO2 (server + browser client) |
| 17 | `@exortek/opaque` | OPAQUE (aPAKE) — zero-knowledge password auth |
| 18 | `@exortek/paseto` | PASETO v4 (`local` / `public`) |
| 19 | `@exortek/oauth2` | OAuth 2.1 client (PKCE) + provider presets |
| 20 | `@exortek/oidc` | OpenID Connect on top of `oauth2` |
| 21 | `@exortek/web3-evm` | SIWE — Sign-In With Ethereum |
| 22 | `@exortek/web3-solana` | SIWS — Sign-In With Solana |
| 23 | `@exortek/auth` | umbrella — re-exports every package above; the one-line install |

## Install

Grab the packages you need directly:

```bash
npm install @exortek/crypto
```

Node.js **22 or newer**.

## Quick start

```js
import { random, hash, cipher, sign } from '@exortek/crypto'

// A 6-digit OTP that will never render '000000'
const otp = random.pin(6)

// A webhook signature you can safely compare in a handler
const ok = hash.verifyHmac(body, req.headers['x-signature'], WEBHOOK_SECRET)

// A cookie-safe encrypted, authenticated string
const key   = await cipher.generateKey()
const token = cipher.encryptToString({ userId: 42 }, key)

// A 1-hour password-reset ticket — payload is private, expiry is unforgeable
const ticket = cipher.seal({ userId: 42, purpose: 'pw-reset' }, RESET_SECRET, {
  ttl: '1h',
})

// A JOSE-standard signature with the JWK thumbprint as `kid`
const kp  = await sign.generateSignKeyPair('es256')
const sig = sign.sign('claim=1', kp.privateKey, { algo: 'es256' })
const kid = sign.thumbprint(kp.publicKey)
```

Full reference on the [documentation site](https://auth.memet.dev) and
in each package's README.

## Design principles

- **One primitive, one purpose.** Every export has a single, boring,
  documented behaviour. `hash.hmac` computes an HMAC — nothing else.
- **Safe defaults, obvious escape hatches.** `random.pin(6)` never
  returns `'000000'`. `cipher.seal` uses AES-256-GCM with an
  unforgeable expiry. Tuning knobs exist for the few callers that need
  them; the defaults are the OWASP cheat sheet.
- **Zero runtime dependencies.** `node:crypto` is the only runtime
  input for every package. The single planned exception is
  `@exortek/web3-evm`, which delegates secp256k1 arithmetic to
  `ethereum-cryptography` because implementing that curve is a bad idea.
- **JavaScript with types anyway.** Source is `.js` with JSDoc; `.d.ts`
  is emitted at build. IDE hints work, strict TypeScript projects
  consume it cleanly, and you never look at a `.tsx`.
- **Tests use `node --test`.** No Jest, no Mocha, no Vitest. Colocated
  `*.test.js` files, native `assert/strict`. The framework ships with
  Node.

## Layout

```
auth/
├── packages/
│   ├── crypto/                # shipping
│   ├── password/              # planned
│   ├── jwt/                   # planned
│   └── …                      # 20+ more per the plan above
├── web/                       # docs site (Next.js + Nextra)
├── ARCHITECTURE.md            # design doc for the whole stack
├── CONTRIBUTING.md
└── LICENSE
```

## Repository

- **Docs:** [auth.memet.dev](https://auth.memet.dev)
- **Contributing:** [CONTRIBUTING.md](./CONTRIBUTING.md) — branch prefixes,
  commit conventions, changeset flow.
- **Architecture:** [ARCHITECTURE.md](./ARCHITECTURE.md) — full design doc.
- **Issues & discussions:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Security:** email `memet@memet.dev` or open a private security
  advisory on the repo.

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
