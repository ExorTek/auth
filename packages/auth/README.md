# @exortek/auth

> The complete `@exortek` authentication toolkit in a single install — framework-agnostic, server-only, types included.

[![npm](https://img.shields.io/npm/v/@exortek/auth.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/auth)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/auth.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/auth)](https://packagephobia.com/result?p=@exortek/auth)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/auth.svg?color=blue)](https://github.com/ExorTek/auth/blob/master/LICENSE)

One package that re-exports every `@exortek/*` primitive — JWT, JWE, JWS, JWK, JWKS, PASETO, password hashing, OTP,
passkeys, magic links, opaque tokens, sessions, API keys, OAuth 2.1, OpenID Connect, the defensive HTTP layer, and
UA/bot detection. Import a namespace for the whole surface, or reach a single subpath when you want to keep your
dependency graph tight.

📖 **Docs:** [**auth.memet.dev**](https://auth.memet.dev)

## Why

The `@exortek` stack is deliberately split into ~19 focused, independently versioned packages. That is the right shape
for a library author who wants `jwt` without dragging in `oauth2`. But an application usually wants _most_ of it, and
juggling nineteen entries in `package.json` — each with its own version to keep aligned — is friction that adds nothing.

`@exortek/auth` is the batteries-included entry point:

- **One install, one version.** `npm install @exortek/auth` pins every primitive at a set of ranges that are known to
  work together.
- **Zero re-bundling.** Every export is a thin `export * from '@exortek/<pkg>'` shim — the same module objects the leaf
  packages expose, byte-for-byte. No copies, no wrappers, no behavioural drift. Your bundler still tree-shakes each
  subpath independently.
- **Namespace _or_ subpath.** `import { jwt } from '@exortek/auth'` for the ergonomic path;
  `import { fastify } from '@exortek/auth/jwt/token-pair'` when you care about the graph. Both resolve to the identical
  code.
- **Types included.** Pure JavaScript source, `.d.ts` emitted at build. Every namespace and every subpath is typed.

If you are shipping _one_ primitive, install that package directly. If you are building an app, install this.

## Install

```bash
npm  install @exortek/auth
yarn add     @exortek/auth
pnpm add     @exortek/auth
```

Requires **Node.js 22 or newer**. `express` and `fastify` are optional peers — only needed if you import a framework
adapter subpath.

## Quick start

```js
import { password, jwt } from '@exortek/auth';

// Register
const hash = await password.hash(plaintext);

// Login → issue a refresh/access pair with reuse detection
const ok = await password.verify(plaintext, hash);
if (!ok) throw new Error('Invalid credentials');

const { accessToken, refreshToken } = await jwt.tokenPair.create(
  { userId: user.id },
  { secret, access: { expiresIn: '15m' }, refresh: { expiresIn: '7d', opaque: true, store } },
);
```

Every namespace is the leaf package's full surface:

```js
import { otp, challenge, session, oauth2, oidc, security, passkey, ua } from '@exortek/auth';

const code = otp.totp.generate(secret);
const guard = security.rateLimit({ window: '1m', max: 60 });
const bot = ua.isBot(req.headers['user-agent']);
```

### Subpath imports

Prefer subpaths when you want to keep the resolved graph minimal — they resolve to the exact same code as the namespace
form:

```js
import { tokenPair } from '@exortek/auth/jwt/token-pair';
import { google } from '@exortek/auth/oauth2/providers/google';
import { fastify } from '@exortek/auth/security/fastify';
import { hash } from '@exortek/auth/crypto/hash';
```

## Modules

Every leaf package is re-exported as a namespace (root import) **and** forwarded at a matching subpath. The namespace
binding is the second column; the leaf package owns the full API and its own README.

| Namespace   | Package                                                                                  | Covers                                                                    |
|-------------|------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `crypto`    | [`@exortek/crypto`](https://github.com/ExorTek/auth/tree/master/packages/crypto)         | Hash, HMAC, KDFs, AEAD cipher, signatures, CSPRNG, encoders               |
| `jwk`       | [`@exortek/jwk`](https://github.com/ExorTek/auth/tree/master/packages/jwk)               | JSON Web Key — generate / import / export / thumbprint / validate         |
| `jws`       | [`@exortek/jws`](https://github.com/ExorTek/auth/tree/master/packages/jws)               | JSON Web Signature — sign / verify / decode / JSON serialization          |
| `jwt`       | [`@exortek/jwt`](https://github.com/ExorTek/auth/tree/master/packages/jwt)               | JSON Web Token — sign / verify + refresh token pairs with reuse detection |
| `jwe`       | [`@exortek/jwe`](https://github.com/ExorTek/auth/tree/master/packages/jwe)               | JSON Web Encryption — encrypt / decrypt / decode / JSON serialization     |
| `jwks`      | [`@exortek/jwks`](https://github.com/ExorTek/auth/tree/master/packages/jwks)             | JSON Web Key Set — local rotation + remote fetch with caching             |
| `opaque`    | [`@exortek/opaque`](https://github.com/ExorTek/auth/tree/master/packages/opaque)         | Opaque reference tokens — no embedded payload, store-backed               |
| `paseto`    | [`@exortek/paseto`](https://github.com/ExorTek/auth/tree/master/packages/paseto)         | PASETO v4 — local / public tokens + refresh pairs                         |
| `password`  | [`@exortek/password`](https://github.com/ExorTek/auth/tree/master/packages/password)     | Argon2 / scrypt / bcrypt / pbkdf2, strength, policy, HIBP                 |
| `otp`       | [`@exortek/otp`](https://github.com/ExorTek/auth/tree/master/packages/otp)               | TOTP / HOTP, backup codes, enrollment, otpauth URIs                       |
| `challenge` | [`@exortek/challenge`](https://github.com/ExorTek/auth/tree/master/packages/challenge)   | Signed single-use challenge tokens for multi-step flows                   |
| `magicLink` | [`@exortek/magic-link`](https://github.com/ExorTek/auth/tree/master/packages/magic-link) | Passwordless email-link auth — HMAC-signed, store-backed                  |
| `passkey`   | [`@exortek/passkey`](https://github.com/ExorTek/auth/tree/master/packages/passkey)       | WebAuthn / FIDO2 server verification, MDS, AAGUID                         |
| `session`   | [`@exortek/session`](https://github.com/ExorTek/auth/tree/master/packages/session)       | Sealed-cookie sessions — rotation, revocation, sudo, trusted devices      |
| `security`  | [`@exortek/security`](https://github.com/ExorTek/auth/tree/master/packages/security)     | CSRF, rate limiting, headers, CORS, redirect safety                       |
| `ua`        | [`@exortek/ua`](https://github.com/ExorTek/auth/tree/master/packages/ua)                 | User-Agent parsing, bot / AI-crawler detection, fingerprinting            |
| `apiKey`    | [`@exortek/apikey`](https://github.com/ExorTek/auth/tree/master/packages/apikey)         | Stripe-style prefixed API keys — mint / verify / rotate                   |
| `oauth2`    | [`@exortek/oauth2`](https://github.com/ExorTek/auth/tree/master/packages/oauth2)         | OAuth 2.1 relying-party + authorization server, 24 provider presets       |
| `oidc`      | [`@exortek/oidc`](https://github.com/ExorTek/auth/tree/master/packages/oidc)             | OpenID Connect Core 1.0 — client + provider on top of `oauth2`            |

Each subpath the leaf package publishes is forwarded verbatim — e.g. `@exortek/auth/oauth2/providers/github`,
`@exortek/auth/crypto/cipher`, `@exortek/auth/session/stores/redis`, `@exortek/auth/ua/middleware/fastify`. See each
package's README for its complete subpath list.

## Why not

Deliberate omissions — these will **not** be added:

- **No aggregating API.** The umbrella never introduces a `createAuth()` god-object or its own helpers. It re-exports;
  it does not abstract. Anything worth building lives in a leaf package where it can be versioned and tested on its own.
- **No renamed bindings.** A namespace is exactly what the leaf package exports. `auth.jwt` _is_ `@exortek/jwt`.
- **No hidden bundling.** Nothing is inlined. Every leaf stays a real, independently resolvable dependency — audit the
  tarball and you will find nineteen `export * from` shims and nothing else.
- **Not for single-primitive installs.** If you only need `jwt`, install `@exortek/jwt`. The umbrella exists for apps.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](https://github.com/ExorTek/auth/blob/master/packages/auth/CHANGELOG.md)

## License

MIT © [ExorTek](https://github.com/ExorTek)
