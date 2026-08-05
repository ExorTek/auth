# @exortek/auth

**Authentication primitives you don't hand-assemble.** A framework-agnostic toolkit for Node.js 22+, built as 20 small
packages under one scope — password hashing, OTP, sessions, passkeys, API keys, and the full RFC-compliant JOSE stack.
Every package is built on `node:crypto`, ships secure defaults, and installs on its own. **18 published today**, the
rest planned.

[![license](https://img.shields.io/github/license/ExorTek/auth?color=blue)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D22-339933)](https://nodejs.org)
[![docs](https://img.shields.io/badge/docs-auth.memet.dev-cb3837)](https://auth.memet.dev)

## Why

- **Secure by default** — mandatory algorithm allowlists, timing-safe comparisons, AEAD ciphers; `alg:none` and
  `RSA1_5` refused everywhere.
- **Zero-dependency core** — built on `node:crypto`; heavy primitives (Argon2id, bcrypt) are opt-in peers you install
  only if you use them.
- **RFC-compliant JOSE** — JWK · JWS · JWT · JWE · JWKS built to spec, with pinned test vectors for cross-vendor interop.
- **Framework-agnostic** — plain functions everywhere, plus first-class Express and Fastify adapters. Adopt one package
  at a time.

## Quick example

```js
import { argon2 } from '@exortek/password';
import { sign, verify } from '@exortek/jwt';
import { jwe } from '@exortek/jwe';

// Hash a password — Argon2id with OWASP defaults.
const phc = await argon2.hash('correct horse battery staple');

// Mint and check a signed token — the alg allowlist is mandatory.
const token = await sign({ sub: 'user-1' }, key, { alg: 'ES256', expiresIn: '15m' });
const { payload } = await verify(token, key, { alg: ['ES256'] });

// Encrypt a token so only the recipient's private key can read it.
const encrypted = await jwe.encrypt(payload, recipientPublicKey, { alg: 'ECDH-ES+A256KW', enc: 'A256GCM' });
```

## Documentation

Full reference, guides, and compliance mapping live at **[auth.memet.dev](https://auth.memet.dev)**.

- **[Guides →](https://auth.memet.dev/guides)** — end-to-end flows: email + password login, JWT access + refresh, 2FA,
  passkeys, passwordless magic links, API keys, and more.
- **[Comparison →](https://auth.memet.dev/comparison)** — how it stacks up against `jose`, `jsonwebtoken`, and Passport.
- **[Compliance →](https://auth.memet.dev/compliance)** — NIST / OWASP ASVS / PCI-DSS / FIPS mapping.

## Shipping

| Package                                                                                                                                                                           |                                                          Version                                                           | Docs                                                       |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------:|------------------------------------------------------------|
| [`@exortek/crypto`](./packages/crypto) — hash · hmac · KDFs · cipher · sign · seal · encode · CSPRNG                                                                              |   [![npm](https://img.shields.io/npm/v/@exortek/crypto.svg?color=07d600)](https://www.npmjs.com/package/@exortek/crypto)   | [auth.memet.dev/crypto](https://auth.memet.dev/crypto)     |
| [`@exortek/security`](./packages/security) — CSRF · rate-limit · headers · CORS · safe-redirect · webhook verify (+ Stripe) + adapters for Fastify · Express                      | [![npm](https://img.shields.io/npm/v/@exortek/security.svg?color=07d600)](https://www.npmjs.com/package/@exortek/security) | [auth.memet.dev/security](https://auth.memet.dev/security) |
| [`@exortek/otp`](./packages/otp) — RFC 4226 HOTP + RFC 6238 TOTP with backup codes, provisioning URI, replay defense                                                              |      [![npm](https://img.shields.io/npm/v/@exortek/otp.svg?color=07d600)](https://www.npmjs.com/package/@exortek/otp)      | [auth.memet.dev/otp](https://auth.memet.dev/otp)           |
| [`@exortek/password`](./packages/password) — Argon2id / scrypt / bcrypt / PBKDF2 + strength / policy / generate / pepper (rotation) / history / HIBP + constant-time verify       | [![npm](https://img.shields.io/npm/v/@exortek/password.svg?color=07d600)](https://www.npmjs.com/package/@exortek/password) | [auth.memet.dev/password](https://auth.memet.dev/password) |
| [`@exortek/session`](./packages/session) — sealed-cookie sessions, rotation, revocation, sudo mode, impersonation, concurrent limits, Redis pub/sub + Fastify/Express             |  [![npm](https://img.shields.io/npm/v/@exortek/session.svg?color=07d600)](https://www.npmjs.com/package/@exortek/session)  | [auth.memet.dev/session](https://auth.memet.dev/session)   |
| [`@exortek/jwk`](./packages/jwk) — generate / import / export JWK ↔ PEM (EC · RSA · OKP · oct), RFC 7638 + 9278 thumbprints, `toPublic()` / `matches()` differentiators           |      [![npm](https://img.shields.io/npm/v/@exortek/jwk.svg?color=07d600)](https://www.npmjs.com/package/@exortek/jwk)      | [auth.memet.dev/jwk](https://auth.memet.dev/jwk)           |
| [`@exortek/jws`](./packages/jws) — JSON Web Signature (RFC 7515) — compact + JSON serialisation, detached (§F), unencoded payload (RFC 7797), HS / RS / PS / ES / EdDSA           |      [![npm](https://img.shields.io/npm/v/@exortek/jws.svg?color=07d600)](https://www.npmjs.com/package/@exortek/jws)      | [auth.memet.dev/jws](https://auth.memet.dev/jws)           |
| [`@exortek/jwt`](./packages/jwt) — JSON Web Token (RFC 7519 + RFC 8725 + RFC 9068) — `sign` / `verify` / `peek`, `tokenPair` with RFC 6749 §10.4 reuse detection, blacklist stores |      [![npm](https://img.shields.io/npm/v/@exortek/jwt.svg?color=07d600)](https://www.npmjs.com/package/@exortek/jwt)      | [auth.memet.dev/jwt](https://auth.memet.dev/jwt)           |
| [`@exortek/challenge`](./packages/challenge) — HMAC-signed multi-step flow tokens (userId · method · step · nextStep · metadata), opt-in single-use + IP binding, memory / Redis stores |      [![npm](https://img.shields.io/npm/v/@exortek/challenge.svg?color=07d600)](https://www.npmjs.com/package/@exortek/challenge)      | [auth.memet.dev/challenge](https://auth.memet.dev/challenge) |
| [`@exortek/apikey`](./packages/apikey) — Stripe-style prefixed API keys (`sk_live_id_secret`) with HMAC-SHA256 storage + optional pepper rotation, scope allowlists, memory / Redis stores, Express + Fastify middleware |      [![npm](https://img.shields.io/npm/v/@exortek/apikey.svg?color=07d600)](https://www.npmjs.com/package/@exortek/apikey)      | [auth.memet.dev/apikey](https://auth.memet.dev/apikey) |
| [`@exortek/magic-link`](./packages/magic-link) — passwordless email-link auth — HMAC-signed short-lived tokens, single-use consume, opt-in per-email rate limit, memory / Redis stores; you send the email |      [![npm](https://img.shields.io/npm/v/@exortek/magic-link.svg?color=07d600)](https://www.npmjs.com/package/@exortek/magic-link)      | [auth.memet.dev/magic-link](https://auth.memet.dev/magic-link) |
| [`@exortek/jwks`](./packages/jwks) — JWK Set (RFC 7517 §5) — local key set with zero-downtime rotation + remote JWKS URI fetching with kid-miss refetch, `/.well-known/jwks.json` handler |      [![npm](https://img.shields.io/npm/v/@exortek/jwks.svg?color=07d600)](https://www.npmjs.com/package/@exortek/jwks)      | [auth.memet.dev/jwks](https://auth.memet.dev/jwks) |
| [`@exortek/ua`](./packages/ua) — User-Agent parsing, device/browser/bot detection, Client Hints, fingerprinting + Express/Fastify middleware + bot-guard |      [![npm](https://img.shields.io/npm/v/@exortek/ua.svg?color=07d600)](https://www.npmjs.com/package/@exortek/ua)      | [auth.memet.dev/ua](https://auth.memet.dev/ua) |
| [`@exortek/opaque`](./packages/opaque) — opaque reference tokens, RFC 7662 introspection + RFC 7009 revocation HTTP handlers, memory / Redis stores |      [![npm](https://img.shields.io/npm/v/@exortek/opaque.svg?color=07d600)](https://www.npmjs.com/package/@exortek/opaque)      | [auth.memet.dev/opaque](https://auth.memet.dev/opaque) |
| [`@exortek/passkey`](./packages/passkey) — WebAuthn Level 3 / FIDO2 server verification, all seven attestation formats, MDS3 + AAGUID subpaths, extension I/O |      [![npm](https://img.shields.io/npm/v/@exortek/passkey.svg?color=07d600)](https://www.npmjs.com/package/@exortek/passkey)      | [auth.memet.dev/passkey](https://auth.memet.dev/passkey) |
| [`@exortek/jwe`](./packages/jwe) — JSON Web Encryption (RFC 7516) — compact + JSON serialisation, RSA-OAEP · ECDH-ES (direct + A128/256KW) · AES-KW · dir over AES-GCM / AES-CBC-HMAC, mandatory alg+enc allowlist, `RSA1_5` refused |      [![npm](https://img.shields.io/npm/v/@exortek/jwe.svg?color=07d600)](https://www.npmjs.com/package/@exortek/jwe)      | [auth.memet.dev/jwe](https://auth.memet.dev/jwe) |
| [`@exortek/paseto`](./packages/paseto) — PASETO v4 — `v4.local` (XChaCha20 + keyed BLAKE2b) · `v4.public` (Ed25519), no `alg` header, `tokenPair` with RFC 6749 §10.4 reuse detection, memory / Redis stores |      [![npm](https://img.shields.io/npm/v/@exortek/paseto.svg?color=07d600)](https://www.npmjs.com/package/@exortek/paseto)      | [auth.memet.dev/paseto](https://auth.memet.dev/paseto) |
| [`@exortek/oauth2`](./packages/oauth2) — OAuth 2.1 — `createOAuth` RP flow + 18 provider presets, login middleware (web + api), and a full authorization server (DPoP · PAR · PKCE · JAR/JARM · device · token-exchange · FAPI) over jwt / paseto |      [![npm](https://img.shields.io/npm/v/@exortek/oauth2.svg?color=07d600)](https://www.npmjs.com/package/@exortek/oauth2)      | [auth.memet.dev/oauth2](https://auth.memet.dev/oauth2) |

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
| 08 | [`@exortek/jwe`](./packages/jwe)           | shipped   | JWE encrypted payloads — RSA-OAEP, ECDH-ES (direct + A128/256KW), AES-KW, dir over AES-GCM / AES-CBC-HMAC |
| 09 | [`@exortek/jwks`](./packages/jwks)         | shipped   | JWKS local key set + remote URI fetching, caching, zero-downtime `kid` rotation          |
| 10 | [`@exortek/session`](./packages/session)   | shipped   | sealed cookies, rotation, revocation, sudo mode, impersonation, Redis pub/sub            |
| 11 | [`@exortek/security`](./packages/security) | shipped   | CSRF, rate-limit, helmet-style headers, CORS, safe-redirect + defensive HTTP helpers     |
| 12 | [`@exortek/ua`](./packages/ua)             | shipped   | User-Agent parsing, device/browser/bot detection, Client Hints, fingerprinting           |
| 13 | [`@exortek/apikey`](./packages/apikey)     | shipped   | Stripe-style prefixed API keys, HMAC-hashed storage, scopes, middleware                  |
| 14 | [`@exortek/magic-link`](./packages/magic-link) | shipped   | passwordless email-link auth — HMAC-signed short-lived tokens with single-use consume    |
| 15 | [`@exortek/passkey`](./packages/passkey)   | shipped   | WebAuthn Level 3 / FIDO2 server verification — all seven attestation formats + MDS3 + AAGUID |
| 16 | [`@exortek/opaque`](./packages/opaque)     | shipped   | opaque reference tokens — RFC 7662 introspection + RFC 7009 revocation HTTP handlers      |
| 17 | [`@exortek/paseto`](./packages/paseto)     | shipped   | PASETO v4 — `v4.local` (XChaCha20 + keyed BLAKE2b) / `v4.public` (Ed25519), no `alg` header, tokenPair with reuse detection |
| 18 | [`@exortek/oauth2`](./packages/oauth2)     | shipped   | OAuth 2.1 — RP flow + 18 provider presets, login middleware, full authorization server (DPoP · PAR · JAR/JARM · device · token-exchange · dynamic registration · opt-in OIDC id_token · FAPI) |
| 19 | `@exortek/oidc`                            | _planned_ | OpenID Connect on top of `oauth2`                                                        |
| 20 | `@exortek/auth`                            | _planned_ | umbrella — re-exports every package above                                                |

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
npm install @exortek/jwe
npm install @exortek/ua                 # + optional: express or fastify
npm install @exortek/opaque             # + optional: ioredis or redis, express or fastify
npm install @exortek/passkey            # + optional: ioredis or redis, express or fastify
npm install @exortek/paseto             # + optional: ioredis or redis
npm install @exortek/oauth2             # + optional: ioredis or redis, express or fastify
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
