# @exortek/oauth2

> OAuth 2.1 for Node.js 22+ — authorization-code + **PKCE (S256)**, `state` / `nonce` CSRF protection, and provider presets. Server-only, zero non-`@exortek/*` runtime dependencies, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/oauth2.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/oauth2)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/oauth2.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/oauth2)](https://packagephobia.com/result?p=@exortek/oauth2)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
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

## Log in with a provider

`createOAuth` is the high-level relying-party flow — the `passport`
replacement. You bring the provider presets and a callback route; it owns
the PKCE / `state` / `nonce` round-trip and hands you the resolved user.

```js
import { createOAuth } from '@exortek/oauth2';
import { google } from '@exortek/oauth2/providers/google';
import { github } from '@exortek/oauth2/providers/github';

const oauth = createOAuth({
  baseUrl: 'https://app.example.com',
  callback: '/auth/{provider}/callback',
  providers: [
    google({ clientId: process.env.GOOGLE_ID, clientSecret: process.env.GOOGLE_SECRET }),
    github({ clientId: process.env.GITHUB_ID, clientSecret: process.env.GITHUB_SECRET }),
  ],
});

// 1. Start — redirect the user, stash the opaque session (cookie / store).
const { url, session } = await oauth.authorize('google');

// 2. Finish — on the callback route, hand back the session + query params.
const { user } = await oauth.callback('google', req.query, { session });
```

### Framework middleware

`mountOAuthLogin` wires the login + callback routes for you — every
platform from one backend, `mode: 'web'` (browser redirect + signed/sealed
cookie or store) or `mode: 'api'` (client-held session for mobile / SPA).

`oauthLogin` returns the `{ start, callback }` handlers — drop them on your
own routes (the same factory idiom as `apiKeyMiddleware`):

```js
import { oauthLogin } from '@exortek/oauth2/express';

const login = oauthLogin({
  oauth,
  cookie: { secret: process.env.SESSION_SECRET }, // signs the flow session; `seal: 'jwe'` also encrypts it
  onSuccess: ({ req, res, user }) => res.redirect('/'),
});

app.get('/auth/:provider', login.start);
app.get('/auth/:provider/callback', login.callback); // must match createOAuth's `callback` template
```

Prefer one call? `mountOAuthLogin(app, { oauth, cookie: { secret } })` registers
both routes for you. Fastify is the same flow as a plugin:

```js
import { oauthLoginPlugin } from '@exortek/oauth2/fastify';

await app.register(oauthLoginPlugin, { oauth, mode: 'api', secret: process.env.SESSION_SECRET });
```

Runnable Express + Fastify programs (plus a browser-clickable local demo that
needs no real provider) live in [`examples/`](./examples).

## Run an authorization server

`createServer` is the OAuth 2.1 authorization server — one framework-agnostic
core, mounted through the `./server/express` or `./server/fastify` adapter.

```js
import { createServer, jwtIssuer } from '@exortek/oauth2/server';
import { mountOAuth2Server } from '@exortek/oauth2/server/express';

const server = createServer({
  issuer: 'https://as.example.com',
  clients: [{ clientId: 'app', clientSecret: process.env.APP_SECRET, redirectUris: ['https://app.example.com/cb'] }],
  tokens: jwtIssuer({ signingKey, alg: 'ES256' }), // RFC 9068 at+jwt; pasetoIssuer is pluggable
  authenticateUser: req => resolveLoggedInUser(req), // your login + consent UI
});

mountOAuth2Server(app, server); // /authorize /token /revoke /introspect /par /device_authorization + metadata
```

Want route-level control? `oauth2Handlers(server)` returns the per-endpoint
handlers to mount yourself (with your own paths / middleware) — the same factory
idiom as `oauthLogin`; `mountOAuth2Server` is sugar over it.

Endpoints: authorize / token / revoke / introspect / PAR / device, RFC 8414
metadata, plus the modern hardening — DPoP (RFC 9449, incl. the nonce
challenge), PKCE, PAR (RFC 9126), resource indicators (RFC 8707), RAR
(RFC 9396), JAR/JARM (RFC 9101), `private_key_jwt` / `client_secret_jwt`
(RFC 7523), mTLS (RFC 8705), token exchange (RFC 8693), and the FAPI 2.0
profile. Resource servers get `verifyDpopForResource` for the `ath` /
`cnf.jkt` check.

### OpenID Connect (opt-in)

Pass an `oidc` config and the server becomes an OpenID Provider: it issues a
signed `id_token` (with `nonce`, `auth_time`, `at_hash`) whenever a request is
granted the `openid` scope, and serves `/.well-known/openid-configuration`.
Leave it off and the server stays a plain OAuth 2.1 AS — no `id_token`, no OIDC
discovery document. The `id_token` is always a JWS, independent of whether
access tokens are JWT or PASETO.

```js
const server = createServer({
  issuer: 'https://as.example.com',
  clients,
  tokens: jwtIssuer({ signingKey, alg: 'ES256' }),
  authenticateUser: req => resolveLoggedInUser(req), // may return { subject, authTime }
  oidc: { idToken: { signingKey, alg: 'ES256' } }, // → OpenID Provider
});
```

### Dynamic client registration (RFC 7591, opt-in)

Add a `registration` config to expose `/register`. It is **initial-access-token
gated by default** (open registration must be explicit) — an open endpoint lets
anyone mint clients. A registered client is validated + frozen through
`defineClient` and immediately usable.

```js
const server = createServer({
  /* … */
  clients: createClientRegistry([]), // a registry that can persist new clients
  registration: { initialAccessToken: process.env.REGISTRATION_TOKEN },
});
// POST /register  Authorization: Bearer <token>  { "redirect_uris": ["https://c/cb"], … }
// → 201 { client_id, client_secret, … }
```

## Modules

| Subpath                          | Status | Purpose                                                                      |
| -------------------------------- | ------ | ---------------------------------------------------------------------------- |
| `@exortek/oauth2`                | ✅     | `createOAuth` RP flow, PKCE (RFC 7636), `state` / `nonce`, `OAuth2Error`      |
| `@exortek/oauth2/express`        | ✅     | `mountOAuthLogin` — Express login + callback middleware (web + api modes)     |
| `@exortek/oauth2/fastify`        | ✅     | `mountOAuthLogin` — Fastify login + callback plugin                           |
| `@exortek/oauth2/providers/*`    | ✅     | Pre-wired presets (google, github, microsoft, apple, okta, …)                 |
| `@exortek/oauth2/server`         | ✅     | `createServer` + `jwtIssuer` / `pasetoIssuer` + `verifyDpopForResource`       |
| `@exortek/oauth2/server/express` | ✅     | `mountOAuth2Server` — mount the AS on Express                                 |
| `@exortek/oauth2/server/fastify` | ✅     | `oauth2ServerPlugin` — mount the AS on Fastify                                |

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
