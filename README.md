# @exortek/auth

A framework-agnostic, zero-dependency authentication toolkit for Node.js —
built as 23 small packages under one scope. Pick the one you need, or
install the umbrella.

[![license](https://img.shields.io/github/license/ExorTek/auth?color=blue)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D22-339933)](https://nodejs.org)
[![docs](https://img.shields.io/badge/docs-auth.memet.dev-cb3837)](https://auth.memet.dev)

## Shipping

| Package | Version | Docs |
| --- | :---: | --- |
| [`@exortek/crypto`](./packages/crypto) — hash · hmac · KDFs · cipher · sign · seal · encode · CSPRNG | [![npm](https://img.shields.io/npm/v/@exortek/crypto.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/crypto) | [auth.memet.dev/crypto](https://auth.memet.dev/crypto) |

## The stack

Numbers reflect dependency order — a lower number never imports from a
higher one, so you adopt one package at a time.

| #  | Package                | What it does                                               |
|:--:|------------------------|------------------------------------------------------------|
| 01 | `@exortek/crypto`      | crypto primitives — the foundation the rest builds on      |
| 02 | `@exortek/password`    | Argon2id / bcrypt, strength scoring, HIBP breach check     |
| 03 | `@exortek/otp`         | TOTP / HOTP, backup codes, QR provisioning URI             |
| 04 | `@exortek/challenge`   | e-mail / SMS one-time code storage + verification          |
| 05 | `@exortek/jwk`         | JWK ↔ PEM ↔ DER converters, key rotation                   |
| 06 | `@exortek/jws`         | JOSE signed payloads (compact + JSON)                      |
| 07 | `@exortek/jwt`         | JWT sign / verify with algorithm allowlists, clock skew    |
| 08 | `@exortek/jwe`         | JWE encrypted payloads (RSA-OAEP, A256KW, dir)             |
| 09 | `@exortek/jwks`        | JWKS URI fetching, caching, `kid` rotation                 |
| 10 | `@exortek/session`     | signed cookies, rotation, revocation, store adapter        |
| 11 | `@exortek/csrf`        | double-submit + signed origin-bound tokens                 |
| 12 | `@exortek/rate-limit`  | token bucket, sliding window, per-IP / per-user            |
| 13 | `@exortek/device`      | device fingerprinting, trusted-device tokens               |
| 14 | `@exortek/apikey`      | prefixed API keys (`sk_live_...`), rate-limited by default |
| 15 | `@exortek/magic-link`  | passwordless email / SMS link tokens                       |
| 16 | `@exortek/passkey`     | WebAuthn / FIDO2 (server + browser client)                 |
| 17 | `@exortek/opaque`      | OPAQUE (aPAKE) — zero-knowledge password auth              |
| 18 | `@exortek/paseto`      | PASETO v4 (`local` / `public`)                             |
| 19 | `@exortek/oauth2`      | OAuth 2.1 client (PKCE) + provider presets                 |
| 20 | `@exortek/oidc`        | OpenID Connect on top of `oauth2`                          |
| 21 | `@exortek/web3-evm`    | SIWE — Sign-In With Ethereum                               |
| 22 | `@exortek/web3-solana` | SIWS — Sign-In With Solana                                 |
| 23 | `@exortek/auth`        | umbrella — re-exports every package above                  |

## Install

```bash
npm install @exortek/crypto
```

Node.js **22 or newer**.

## Repository

- **Docs:** [auth.memet.dev](https://auth.memet.dev)
- **Architecture:** [ARCHITECTURE.md](./ARCHITECTURE.md)
- **Contributing:** [CONTRIBUTING.md](./CONTRIBUTING.md)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Security:** email `memet@memet.dev`

MIT © ExorTek.
