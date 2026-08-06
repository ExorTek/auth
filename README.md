# @exortek/auth

**Authentication primitives you don't hand-assemble.** A framework-agnostic toolkit for Node.js 22+ — password
hashing, OTP, sessions, passkeys, API keys, OAuth 2.1, and the full RFC-compliant JOSE stack, split into 20 small
packages under one scope. Every package is built on `node:crypto`, ships secure-by-default, and installs on its own.

[![node](https://img.shields.io/badge/node-%3E%3D22-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org)
[![types](https://img.shields.io/badge/types-included-3178c6?style=flat-square&logo=typescript&logoColor=white)](#)
[![deps](https://img.shields.io/badge/deps-node%3Acrypto-8957e5?style=flat-square)](#why)
[![license](https://img.shields.io/github/license/ExorTek/auth?style=flat-square&color=blue)](./LICENSE)
[![docs](https://img.shields.io/badge/docs-auth.memet.dev-cb3837?style=flat-square&logo=readthedocs&logoColor=white)](https://auth.memet.dev)

**18 of 20 packages published** · [Documentation](https://auth.memet.dev) · [Guides](https://auth.memet.dev/guides) · [Comparison](https://auth.memet.dev/comparison)

## Why

- **Secure by default** — mandatory algorithm allowlists, timing-safe comparisons, AEAD ciphers; `alg:none` and
  `RSA1_5` are refused everywhere, with no flag to turn them back on.
- **Dependency-light core** — built on `node:crypto`. Heavy primitives (Argon2id, bcrypt), Redis clients, and web
  framework adapters are **optional peers** you install only if you use them.
- **RFC-compliant JOSE** — JWK · JWS · JWT · JWE · JWKS built to spec, with pinned test vectors for cross-vendor interop.
- **Framework-agnostic** — plain functions everywhere, plus first-class Express and Fastify adapters. Adopt one
  package at a time; each is fully standalone at runtime.

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

## Install

Requires **Node.js 22+**. Install only the packages you need — each is published independently:

```bash
npm install @exortek/jwt        # …or any package from the table below
```

Some packages pull in **optional peers** only when you use a feature that needs them:

| Peer | Needed for | Packages |
|------|------------|----------|
| `ioredis` **or** `redis` | multi-process stores | apikey · magic-link · opaque · passkey · paseto · session · jwt · oauth2 · security |
| `express` **or** `fastify` | middleware adapters | apikey · opaque · passkey · ua · security · session · oauth2 |
| `argon2` / `bcrypt` | those hash algorithms | password |

## Packages

Numbered by **dependency order** — a lower number never imports from a higher one, so you can adopt one package at a
time. Linked names are **published on npm**; the rest are planned.

| # | Package | npm | What it does |
|:--:|---------|:---:|--------------|
| 01 | [`@exortek/crypto`](https://auth.memet.dev/crypto) | [![v](https://img.shields.io/npm/v/@exortek/crypto?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/crypto) | hash · hmac · KDFs · cipher · sign · seal · encode · CSPRNG — the foundation the rest builds on |
| 02 | [`@exortek/password`](https://auth.memet.dev/password) | [![v](https://img.shields.io/npm/v/@exortek/password?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/password) | Argon2id / scrypt / bcrypt / PBKDF2, strength scoring, HIBP breach check, pepper rotation, history |
| 03 | [`@exortek/otp`](https://auth.memet.dev/otp) | [![v](https://img.shields.io/npm/v/@exortek/otp?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/otp) | RFC 4226 HOTP + RFC 6238 TOTP, backup codes, QR provisioning URI, replay defense |
| 04 | [`@exortek/challenge`](https://auth.memet.dev/challenge) | [![v](https://img.shields.io/npm/v/@exortek/challenge?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/challenge) | HMAC-signed multi-step flow tokens, opt-in single-use + IP binding, memory / Redis stores |
| 05 | [`@exortek/jwk`](https://auth.memet.dev/jwk) | [![v](https://img.shields.io/npm/v/@exortek/jwk?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/jwk) | generate / import / export JWK ↔ PEM (EC · RSA · OKP · oct), RFC 7638 + 9278 thumbprints |
| 06 | [`@exortek/jws`](https://auth.memet.dev/jws) | [![v](https://img.shields.io/npm/v/@exortek/jws?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/jws) | JWS compact + JSON, detached (§F), unencoded payload (RFC 7797), HS / RS / PS / ES / EdDSA |
| 07 | [`@exortek/jwt`](https://auth.memet.dev/jwt) | [![v](https://img.shields.io/npm/v/@exortek/jwt?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/jwt) | JWT sign / verify / peek, `tokenPair` with RFC 6749 §10.4 reuse detection, blacklist stores |
| 08 | [`@exortek/jwe`](https://auth.memet.dev/jwe) | [![v](https://img.shields.io/npm/v/@exortek/jwe?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/jwe) | JWE compact + JSON — RSA-OAEP · ECDH-ES (direct + A128/256KW) · AES-KW · dir, `RSA1_5` refused |
| 09 | [`@exortek/jwks`](https://auth.memet.dev/jwks) | [![v](https://img.shields.io/npm/v/@exortek/jwks?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/jwks) | JWK Set — local set with zero-downtime rotation, remote URI fetch with `kid`-miss refetch |
| 10 | [`@exortek/session`](https://auth.memet.dev/session) | [![v](https://img.shields.io/npm/v/@exortek/session?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/session) | sealed-cookie sessions, rotation, revocation, sudo mode, impersonation, concurrent limits, Redis pub/sub |
| 11 | [`@exortek/security`](https://auth.memet.dev/security) | [![v](https://img.shields.io/npm/v/@exortek/security?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/security) | CSRF · rate-limit · headers · CORS · safe-redirect · webhook verify (+ Stripe) + adapters |
| 12 | [`@exortek/ua`](https://auth.memet.dev/ua) | [![v](https://img.shields.io/npm/v/@exortek/ua?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/ua) | User-Agent parsing, device / browser / bot detection, Client Hints, fingerprinting, bot-guard |
| 13 | [`@exortek/apikey`](https://auth.memet.dev/apikey) | [![v](https://img.shields.io/npm/v/@exortek/apikey?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/apikey) | Stripe-style prefixed API keys, HMAC-SHA256 storage + pepper rotation, scopes, middleware |
| 14 | [`@exortek/magic-link`](https://auth.memet.dev/magic-link) | [![v](https://img.shields.io/npm/v/@exortek/magic-link?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/magic-link) | passwordless email-link auth — HMAC-signed short-lived tokens, single-use consume, rate limit |
| 15 | [`@exortek/passkey`](https://auth.memet.dev/passkey) | [![v](https://img.shields.io/npm/v/@exortek/passkey?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/passkey) | WebAuthn Level 3 / FIDO2 server verification, all seven attestation formats, MDS3 + AAGUID |
| 16 | [`@exortek/opaque`](https://auth.memet.dev/opaque) | [![v](https://img.shields.io/npm/v/@exortek/opaque?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/opaque) | opaque reference tokens, RFC 7662 introspection + RFC 7009 revocation handlers |
| 17 | [`@exortek/paseto`](https://auth.memet.dev/paseto) | [![v](https://img.shields.io/npm/v/@exortek/paseto?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/paseto) | PASETO v4 — `v4.local` (XChaCha20 + BLAKE2b) · `v4.public` (Ed25519), `tokenPair` reuse detection |
| 18 | [`@exortek/oauth2`](https://auth.memet.dev/oauth2) | [![v](https://img.shields.io/npm/v/@exortek/oauth2?style=flat-square&color=07d600&label=)](https://www.npmjs.com/package/@exortek/oauth2) | OAuth 2.1 — `createOAuth` RP flow + 18 provider presets, login middleware, full authorization server (DPoP · PAR · PKCE · JAR/JARM · device · token-exchange · FAPI) |
| 19 | `@exortek/oidc` | _planned_ | OpenID Connect on top of `oauth2` |
| 20 | `@exortek/auth` | _planned_ | umbrella — re-exports every package above |

## Documentation

Full reference, guides, and compliance mapping live at **[auth.memet.dev](https://auth.memet.dev)**.

- **[Guides →](https://auth.memet.dev/guides)** — end-to-end flows: email + password login, JWT access + refresh, 2FA,
  passkeys, passwordless magic links, API keys, and more.
- **[Comparison →](https://auth.memet.dev/comparison)** — how it stacks up against `jose`, `jsonwebtoken`, and Passport.
- **[Compliance →](https://auth.memet.dev/compliance)** — NIST / OWASP ASVS / PCI-DSS / FIPS mapping.

## Repository

- **Architecture:** [ARCHITECTURE.md](./ARCHITECTURE.md)
- **AI agents:** [AGENTS.md](./AGENTS.md)
- **Contributing:** [CONTRIBUTING.md](./CONTRIBUTING.md)
- **Security:** [SECURITY.md](./SECURITY.md) · email `memet@memet.dev`
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)

[MIT](./LICENSE) © ExorTek.
