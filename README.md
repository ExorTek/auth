# @exortek/auth

A framework-agnostic authentication toolkit for Node.js — designed as 22 small packages under one scope; **12 are
published today** (see Shipping below), the rest are planned. Pick the one you need. Built on `node:crypto`.

[![license](https://img.shields.io/github/license/ExorTek/auth?color=blue)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D22-339933)](https://nodejs.org)
[![docs](https://img.shields.io/badge/docs-auth.memet.dev-cb3837)](https://auth.memet.dev)

## Shipping

| Package                                                                                                                                                                           |                                                          Version                                                           | Docs                                                       |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------:|------------------------------------------------------------|
| [`@exortek/crypto`](./packages/crypto) — hash · hmac · KDFs · cipher · sign · seal · encode · CSPRNG                                                                              |   [![npm](https://img.shields.io/npm/v/@exortek/crypto.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/crypto)   | [auth.memet.dev/crypto](https://auth.memet.dev/crypto)     |
| [`@exortek/security`](./packages/security) — CSRF · rate-limit · headers · CORS · safe-redirect · webhook verify (+ Stripe) + adapters for Fastify · Express                      | [![npm](https://img.shields.io/npm/v/@exortek/security.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/security) | [auth.memet.dev/security](https://auth.memet.dev/security) |
| [`@exortek/otp`](./packages/otp) — RFC 4226 HOTP + RFC 6238 TOTP with backup codes, provisioning URI, replay defense                                                              |      [![npm](https://img.shields.io/npm/v/@exortek/otp.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/otp)      | [auth.memet.dev/otp](https://auth.memet.dev/otp)           |
| [`@exortek/password`](./packages/password) — Argon2id / scrypt / bcrypt / PBKDF2 + strength / policy / generate / pepper (rotation) / history / HIBP + constant-time verify       | [![npm](https://img.shields.io/npm/v/@exortek/password.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/password) | [auth.memet.dev/password](https://auth.memet.dev/password) |
| [`@exortek/session`](./packages/session) — sealed-cookie sessions, rotation, revocation, sudo mode, impersonation, concurrent limits, Redis pub/sub + Fastify/Express             |  [![npm](https://img.shields.io/npm/v/@exortek/session.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/session)  | [auth.memet.dev/session](https://auth.memet.dev/session)   |
| [`@exortek/jwk`](./packages/jwk) — generate / import / export JWK ↔ PEM (EC · RSA · OKP · oct), RFC 7638 + 9278 thumbprints, `toPublic()` / `matches()` differentiators           |      [![npm](https://img.shields.io/npm/v/@exortek/jwk.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jwk)      | [auth.memet.dev/jwk](https://auth.memet.dev/jwk)           |
| [`@exortek/jws`](./packages/jws) — JSON Web Signature (RFC 7515) — compact + JSON serialisation, detached (§F), unencoded payload (RFC 7797), HS / RS / PS / ES / EdDSA           |      [![npm](https://img.shields.io/npm/v/@exortek/jws.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jws)      | [auth.memet.dev/jws](https://auth.memet.dev/jws)           |
| [`@exortek/jwt`](./packages/jwt) — JSON Web Token (RFC 7519 + RFC 8725 + RFC 9068) — `sign` / `verify` / `peek`, `tokenPair` with RFC 6749 §10.4 reuse detection, blacklist stores |      [![npm](https://img.shields.io/npm/v/@exortek/jwt.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jwt)      | [auth.memet.dev/jwt](https://auth.memet.dev/jwt)           |
| [`@exortek/challenge`](./packages/challenge) — HMAC-signed multi-step flow tokens (userId · method · step · nextStep · metadata), opt-in single-use + IP binding, memory / Redis stores |      [![npm](https://img.shields.io/npm/v/@exortek/challenge.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/challenge)      | [auth.memet.dev/challenge](https://auth.memet.dev/challenge) |
| [`@exortek/apikey`](./packages/apikey) — Stripe-style prefixed API keys (`sk_live_id_secret`) with HMAC-SHA256 storage + optional pepper rotation, scope allowlists, memory / Redis stores, Express + Fastify middleware |      [![npm](https://img.shields.io/npm/v/@exortek/apikey.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/apikey)      | [auth.memet.dev/apikey](https://auth.memet.dev/apikey) |
| [`@exortek/magic-link`](./packages/magic-link) — passwordless email-link auth — HMAC-signed short-lived tokens, single-use consume, opt-in per-email rate limit, memory / Redis stores; you send the email |      [![npm](https://img.shields.io/npm/v/@exortek/magic-link.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/magic-link)      | [auth.memet.dev/magic-link](https://auth.memet.dev/magic-link) |
| [`@exortek/jwks`](./packages/jwks) — JWK Set (RFC 7517 §5) — local key set with zero-downtime rotation + remote JWKS URI fetching with kid-miss refetch, `/.well-known/jwks.json` handler |      [![npm](https://img.shields.io/npm/v/@exortek/jwks.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/jwks)      | [auth.memet.dev/jwks](https://auth.memet.dev/jwks) |

## The stack

Numbers reflect dependency order — a lower number never imports from a higher one, so you adopt one package at a time.
Linked entries are **published on npm**; the rest are **planned** and not yet installable.

| #  | Package                                    | Status    | What it does                                                                             |
|:--:|--------------------------------------------|-----------|------------------------------------------------------------------------------------------|
| 01 | [`@exortek/crypto`](./packages/crypto)     | shipped   | crypto primitives — the foundation the rest builds on                                    |
| 02 | [`@exortek/password`](./packages/password) | shipped   | Argon2id / scrypt / bcrypt / PBKDF2, strength scoring, HIBP breach check, peppering      |
| 03 | [`@exortek/otp`](./packages/otp)           | shipped   | TOTP / HOTP, backup codes, QR provisioning URI                                           |
| 04 | [`@exortek/challenge`](./packages/challenge) | shipped   | HMAC-signed multi-step flow tokens with opt-in single-use + IP binding                   |
| 05 | [`@exortek/jwk`](./packages/jwk)           | shipped   | generate / import / export JWK ↔ PEM (EC · RSA · OKP · oct), RFC 7638 + 9278 thumbprints |
| 06 | [`@exortek/jws`](./packages/jws)           | shipped   | JWS compact + JSON, detached, `b64:false`, HS / RS / PS / ES / EdDSA + secp256k1          |
| 07 | [`@exortek/jwt`](./packages/jwt)           | shipped   | JWT sign / verify / peek, tokenPair with RFC 6749 §10.4 reuse detection, blacklist stores |
| 08 | `@exortek/jwe`                             | _planned_ | JWE encrypted payloads (RSA-OAEP, A256KW, dir)                                           |
| 09 | [`@exortek/jwks`](./packages/jwks)         | shipped   | JWKS local key set + remote URI fetching, caching, zero-downtime `kid` rotation          |
| 10 | [`@exortek/session`](./packages/session)   | shipped   | sealed cookies, rotation, revocation, sudo mode, impersonation, Redis pub/sub            |
| 11 | [`@exortek/security`](./packages/security) | shipped   | CSRF, rate-limit, helmet-style headers, CORS, safe-redirect + defensive HTTP helpers     |
| 12 | `@exortek/device`                          | _planned_ | device fingerprinting, trusted-device tokens                                             |
| 13 | [`@exortek/apikey`](./packages/apikey)     | shipped   | Stripe-style prefixed API keys, HMAC-hashed storage, scopes, middleware                  |
| 14 | [`@exortek/magic-link`](./packages/magic-link) | shipped   | passwordless email-link auth — HMAC-signed short-lived tokens with single-use consume    |
| 15 | `@exortek/passkey`                         | _planned_ | WebAuthn / FIDO2 server verification (browser side via `@simplewebauthn/browser`)        |
| 16 | `@exortek/opaque`                          | _planned_ | OPAQUE (aPAKE) — zero-knowledge password auth                                            |
| 17 | `@exortek/paseto`                          | _planned_ | PASETO v4 (`local` / `public`)                                                           |
| 18 | `@exortek/oauth2`                          | _planned_ | OAuth 2.1 client (PKCE) + provider presets                                               |
| 19 | `@exortek/oidc`                            | _planned_ | OpenID Connect on top of `oauth2`                                                        |
| 20 | `@exortek/web3-evm`                        | _planned_ | SIWE — Sign-In With Ethereum                                                             |
| 21 | `@exortek/web3-solana`                     | _planned_ | SIWS — Sign-In With Solana                                                               |
| 22 | `@exortek/auth`                            | _planned_ | umbrella — re-exports every package above                                                |

## Install

Every published package is installable on its own:

```bash
npm install @exortek/crypto
npm install @exortek/security
npm install @exortek/otp
npm install @exortek/password
npm install @exortek/session
npm install @exortek/jwk
npm install @exortek/jws
npm install @exortek/jwt
npm install @exortek/challenge
npm install @exortek/apikey             # + optional: ioredis or redis, express or fastify
npm install @exortek/magic-link         # + optional: ioredis or redis
npm install @exortek/jwks
```

Node.js **22 or newer**.

## Repository

- **Docs:** [auth.memet.dev](https://auth.memet.dev)
- **Architecture:** [ARCHITECTURE.md](./ARCHITECTURE.md)
- **AI agents:** [AGENTS.md](./AGENTS.md)
- **Contributing:** [CONTRIBUTING.md](./CONTRIBUTING.md)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Security:** email `memet@memet.dev`

[MIT](/LICENSE) © ExorTek.
