# @exortek/auth

A framework-agnostic authentication toolkit for Node.js — designed as 22 small packages under one scope; **5 are
published today** (see Shipping below), the rest are planned. Pick the one you need. Built on `node:crypto`.

[![license](https://img.shields.io/github/license/ExorTek/auth?color=blue)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D22-339933)](https://nodejs.org)
[![docs](https://img.shields.io/badge/docs-auth.memet.dev-cb3837)](https://auth.memet.dev)

## Shipping

| Package                                                                                                                                                                           |                                                          Version                                                           | Docs                                                       |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------:|------------------------------------------------------------|
| [`@exortek/crypto`](./packages/crypto) — hash · hmac · KDFs · cipher · sign · seal · encode · CSPRNG                                                                              |   [![npm](https://img.shields.io/npm/v/@exortek/crypto.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/crypto)   | [auth.memet.dev/crypto](https://auth.memet.dev/crypto)     |
| [`@exortek/security`](./packages/security) — CSRF · rate-limit · headers · CORS · safe-redirect + adapters for Fastify · Express · Hono · Elysia                                  | [![npm](https://img.shields.io/npm/v/@exortek/security.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/security) | [auth.memet.dev/security](https://auth.memet.dev/security) |
| [`@exortek/otp`](./packages/otp) — RFC 4226 HOTP + RFC 6238 TOTP with backup codes, provisioning URI, replay defense                                                              |      [![npm](https://img.shields.io/npm/v/@exortek/otp.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/otp)      | [auth.memet.dev/otp](https://auth.memet.dev/otp)           |
| [`@exortek/password`](./packages/password) — Argon2id / scrypt / bcrypt / PBKDF2 + strength / policy / generate / pepper (rotation) / history / HIBP + constant-time verify       | [![npm](https://img.shields.io/npm/v/@exortek/password.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/password) | [auth.memet.dev/password](https://auth.memet.dev/password) |
| [`@exortek/session`](./packages/session) — sealed-cookie sessions, rotation, revocation, sudo mode, impersonation, concurrent limits, Redis pub/sub + Fastify/Express/Hono/Elysia |  [![npm](https://img.shields.io/npm/v/@exortek/session.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/session)  | [auth.memet.dev/session](https://auth.memet.dev/session)   |

## The stack

Numbers reflect dependency order — a lower number never imports from a higher one, so you adopt one package at a time.
Linked entries are **published on npm**; the rest are **planned** and not yet installable.

| #  | Package                                    | Status    | What it does                                                                         |
|:--:|--------------------------------------------|-----------|--------------------------------------------------------------------------------------|
| 01 | [`@exortek/crypto`](./packages/crypto)     | shipped   | crypto primitives — the foundation the rest builds on                                |
| 02 | [`@exortek/password`](./packages/password) | shipped   | Argon2id / scrypt / bcrypt / PBKDF2, strength scoring, HIBP breach check, peppering  |
| 03 | [`@exortek/otp`](./packages/otp)           | shipped   | TOTP / HOTP, backup codes, QR provisioning URI                                       |
| 04 | `@exortek/challenge`                       | _planned_ | e-mail / SMS one-time code storage + verification                                    |
| 05 | `@exortek/jwk`                             | _planned_ | JWK ↔ PEM ↔ DER converters, key rotation                                             |
| 06 | `@exortek/jws`                             | _planned_ | JOSE signed payloads (compact + JSON)                                                |
| 07 | `@exortek/jwt`                             | _planned_ | JWT sign / verify with algorithm allowlists, clock skew                              |
| 08 | `@exortek/jwe`                             | _planned_ | JWE encrypted payloads (RSA-OAEP, A256KW, dir)                                       |
| 09 | `@exortek/jwks`                            | _planned_ | JWKS URI fetching, caching, `kid` rotation                                           |
| 10 | [`@exortek/session`](./packages/session)   | shipped   | sealed cookies, rotation, revocation, sudo mode, impersonation, Redis pub/sub        |
| 11 | [`@exortek/security`](./packages/security) | shipped   | CSRF, rate-limit, helmet-style headers, CORS, safe-redirect + defensive HTTP helpers |
| 12 | `@exortek/device`                          | _planned_ | device fingerprinting, trusted-device tokens                                         |
| 13 | `@exortek/apikey`                          | _planned_ | prefixed API keys (`sk_live_...`), rate-limited by default                           |
| 14 | `@exortek/magic-link`                      | _planned_ | passwordless email / SMS link tokens                                                 |
| 15 | `@exortek/passkey`                         | _planned_ | WebAuthn / FIDO2 (server + browser client)                                           |
| 16 | `@exortek/opaque`                          | _planned_ | OPAQUE (aPAKE) — zero-knowledge password auth                                        |
| 17 | `@exortek/paseto`                          | _planned_ | PASETO v4 (`local` / `public`)                                                       |
| 18 | `@exortek/oauth2`                          | _planned_ | OAuth 2.1 client (PKCE) + provider presets                                           |
| 19 | `@exortek/oidc`                            | _planned_ | OpenID Connect on top of `oauth2`                                                    |
| 20 | `@exortek/web3-evm`                        | _planned_ | SIWE — Sign-In With Ethereum                                                         |
| 21 | `@exortek/web3-solana`                     | _planned_ | SIWS — Sign-In With Solana                                                           |
| 22 | `@exortek/auth`                            | _planned_ | umbrella — re-exports every package above                                            |

## Install

Every published package is installable on its own:

```bash
npm install @exortek/crypto
npm install @exortek/security
npm install @exortek/otp
npm install @exortek/password
npm install @exortek/session
```

Node.js **22 or newer**.

## Repository

- **Docs:** [auth.memet.dev](https://auth.memet.dev)
- **Architecture:** [ARCHITECTURE.md](./ARCHITECTURE.md)
- **Contributing:** [CONTRIBUTING.md](./CONTRIBUTING.md)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Security:** email `memet@memet.dev`

MIT © ExorTek.
