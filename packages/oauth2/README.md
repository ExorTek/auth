# @exortek/oauth2

> OAuth 2.1 for Node.js 22+ — authorization-code + **PKCE (S256)**, `state` / `nonce` CSRF protection, and provider presets. Server-only, zero-dependency, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/oauth2.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/oauth2)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/oauth2.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/oauth2)](https://packagephobia.com/result?p=@exortek/oauth2)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![zero-deps](https://img.shields.io/badge/dependencies-0-brightgreen)](./package.json)
[![license](https://img.shields.io/npm/l/@exortek/oauth2.svg?color=blue)](https://github.com/ExorTek/auth/blob/master/LICENSE)

OAuth's footguns all live in the parts people skip: no PKCE, a `state`
that is generated but never checked, a `redirect_uri` matched by prefix,
a token accepted from the wrong issuer. `@exortek/oauth2` makes the
security-critical bits of the authorization-code flow the default,
non-negotiable path — the [design philosophy](https://github.com/ExorTek/auth/blob/master/ARCHITECTURE.md)
of this stack: you should never hand-assemble a login flow out of
`crypto.randomBytes` and string concatenation.

> **OAuth 2.1** (`draft-ietf-oauth-v2-1`) folds the mandatory-PKCE /
> no-implicit-grant / exact-redirect BCPs (RFC 9700) into the base spec.
> This package tracks that draft; it is not yet a published RFC.

📖 **Docs:** [**auth.memet.dev/oauth2**](https://auth.memet.dev/oauth2)

## Why

- **`passport` + a strategy per provider** — battle-tested but callback-era,
  couples you to Express middleware, and leaves PKCE / `state` / issuer
  checks to whichever strategy you picked (quality varies).
- **`openid-client` / `arctic`** — solid, lower-level building blocks; you
  still wire the session binding, the `state` round-trip, and the provider
  quirks yourself.

`@exortek/oauth2` ships the primitive **and** the high-level flow every
login reinvents, with the OAuth 2.0 Security BCP (RFC 9700) baked in:

1. **PKCE is mandatory, `S256` only.** `plain` is not implemented — there
   is no configuration that turns the protection off.
2. **`state` and `nonce` are generated *and* verified.** The round-trip
   is part of the API, not a checklist item.
3. **Exact `redirect_uri` and `iss` matching.** Open-redirect and mix-up
   attacks are rejected structurally, not by convention.
4. **Provider presets** for the common identity providers — each one
   pre-wires the endpoints, scopes, and userinfo mapping.
5. **Zero runtime dependencies.** Built on `node:crypto`.

## Install

```bash
npm install @exortek/oauth2
```

Requires **Node.js 22 or newer**. Server-side only.

## Security primitives

The root entry exposes the flow's building blocks. Both the authorization
server and the provider presets are built on exactly these.

```js
import { createPkcePair, verifyChallenge, randomState, randomNonce } from '@exortek/oauth2';

// Client side of the flow — before redirecting to /authorize:
const { codeVerifier, codeChallenge, codeChallengeMethod } = createPkcePair();
const state = randomState(); // 256-bit, base64url — bind to the session

// Authorization-server side — at the token endpoint:
verifyChallenge(codeVerifier, codeChallenge); // constant-time S256 check
```

## Modules

| Subpath                     | Status  | Purpose                                                                        |
| --------------------------- | ------- | ------------------------------------------------------------------------------ |
| `@exortek/oauth2`           | ✅      | PKCE (RFC 7636), `state` / `nonce` generators, `OAuth2Error` / `ErrorCode`      |
| `@exortek/oauth2/server`    | ⏳      | `createServer` — authorize / token / revoke / introspect / metadata handlers   |
| `@exortek/oauth2/providers/*` | ⏳    | Pre-wired presets (google, github, discord, …) with full flow security         |

## Error handling

Every failure throws `OAuth2Error` with a stable `ErrorCode`. Branch on
`code`, never on the message.

```js
import { OAuth2Error, ErrorCode } from '@exortek/oauth2';

try {
  createPkcePair();
} catch (err) {
  if (!(err instanceof OAuth2Error)) throw err;
  if (err.code === ErrorCode.INVALID_ARGUMENT) {
    /* … */
  }
}
```

## Why not

Deliberate omissions — these will **not** be added:

- **Implicit grant / password grant.** Removed by OAuth 2.1; not a config
  option here.
- **`plain` PKCE.** `S256` only.
- **A browser bundle.** This is server-side code; the `redirect_uri`
  target is your own callback route, not shipped client JS.
- **Callback-style API.** Promise-only; Node 22+.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](https://github.com/ExorTek/auth/blob/master/packages/oauth2/CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](https://github.com/ExorTek/auth/blob/master/LICENSE).
