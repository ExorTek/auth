# @exortek/oidc

> OpenID Connect Core 1.0 for Node.js 22+ — the identity layer on top of **[`@exortek/oauth2`](../oauth2)**. Relying party + OpenID Provider, discovery, UserInfo, RP-Initiated Logout, Session Management. Server-only, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/oidc.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/oidc)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/oidc.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/oidc)](https://packagephobia.com/result?p=@exortek/oidc)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/oidc.svg?color=blue)](https://github.com/ExorTek/auth/blob/master/LICENSE)

`@exortek/oauth2` already speaks OAuth 2.1 and can issue an `id_token`.
`@exortek/oidc` makes **OpenID Connect** the first-class shape on both
sides of the exchange: a discovery-first relying-party client that enforces
the `openid` scope and validates the `id_token` end to end, and an OpenID
Provider add-on that serves discovery, UserInfo, logout and session
management beside your `@exortek/oauth2/server` authorization server.

📖 **Docs:** [**auth.memet.dev/oidc**](https://auth.memet.dev/oidc)

## Why

- **`@exortek/oauth2`** gives you the OAuth 2.1 machinery — PKCE, `state`,
  `nonce`, DPoP, PAR, the authorization server. OIDC is the identity
  contract layered on it: *who the user is*, proven by a signed `id_token`
  and a UserInfo endpoint.
- Bolting OIDC onto a generic OAuth client by hand is where the subtle bugs
  live — a skipped `nonce` check, an unvalidated `aud`, trusting UserInfo
  `sub` over the `id_token` `sub`, a `post_logout_redirect_uri` open
  redirect. This package refuses to let the caller skip them, and reuses
  oauth2's verified flow rather than reimplementing it.

## Modules

| Import | Purpose |
|--------|---------|
| `@exortek/oidc` | Barrel — `createClient`, `createProvider`, `ErrorCode`, `OidcError`. |
| `@exortek/oidc/client` | Relying-party (SSO) client. |
| `@exortek/oidc/client/express` · `/client/fastify` | Browser-login route adapters. |
| `@exortek/oidc/provider` | OpenID Provider add-ons (discovery / UserInfo / JWKS / logout / session). |
| `@exortek/oidc/provider/express` · `/provider/fastify` | Mount the provider endpoints. |

## Install

```bash
npm install @exortek/oidc
```

## Relying party (SSO)

```js
import { createClient } from '@exortek/oidc/client';

const client = createClient({
  issuer: 'https://accounts.google.com',
  clientId: '...',
  clientSecret: '...',
  redirectUri: 'https://myapp.com/callback',
  scope: ['openid', 'email', 'profile'],
});

// 1. Start — redirect the user to `url`, keep `session` (cookie / store).
const { url, session } = await client.authorize({ prompt: 'login' });

// 2. Callback — id_token signature / iss / aud / nonce are verified inside.
const { idToken, claims, userinfo } = await client.handleCallback(req.query, { session });

// 3. Logout (RP-Initiated Logout 1.0)
const logoutUrl = await client.endSessionUrl({
  idTokenHint: idToken,
  postLogoutRedirectUri: 'https://myapp.com/',
  state: 'xyz',
});
```

With Express, the browser flow is two routes:

```js
import { mountOidcLogin } from '@exortek/oidc/client/express';

mountOidcLogin(app, {
  client,
  onSuccess: ({ res, claims }) => {
    req.session.user = claims.sub;
    res.redirect('/');
  },
});
```

## OpenID Provider

`createProvider` supplies the OIDC endpoints to mount **beside** your
`@exortek/oauth2/server` `createServer` (which already issues the
`id_token` off the `openid` scope):

```js
import { createProvider } from '@exortek/oidc/provider';
import { mountOidcProvider } from '@exortek/oidc/provider/express';

const provider = createProvider({
  issuer: 'https://auth.myapp.com',
  signing: { key: signingPrivateJwk, alg: 'ES256', kid: 'key-1' },
  jwks: [publicJwk],                       // published at jwks_uri
  endpoints: { authorization: '/authorize', token: '/token' },
  claims: {
    supported: ['sub', 'email', 'email_verified', 'name', 'picture'],
    userinfo: ['email', 'name', 'picture'],
  },
  userinfo: {
    // turn a Bearer access token into { sub, scope, claims }
    resolve: accessToken => introspect(accessToken),
  },
  logout: { postLogoutRedirectUris: ['https://myapp.com/'] },
  session: { cookieName: 'op_browser_state' },
});

mountOidcProvider(app, provider);
// → /.well-known/openid-configuration, /.well-known/jwks.json,
//   /userinfo, /end_session, /check_session
```

Handlers are framework-agnostic (`{ method, url, headers, query } →
{ status, headers, body }`) — mount them by hand, or use the express /
fastify adapters. `provider.idTokenSigner` is the same signer your
`createServer` should use, so both sign with one key.

## Why not just `@exortek/oauth2`?

Use `@exortek/oauth2` on its own when you need access-token authorization
and nothing more. Reach for `@exortek/oidc` the moment you need
*authentication* — a verified end-user identity — with the OIDC Core
guarantees (nonce, `aud`, `sub` binding, logout, session) enforced rather
than reassembled per app.

## Specifications

- OpenID Connect Core 1.0 · Discovery 1.0 · RP-Initiated Logout 1.0 ·
  Session Management 1.0
- Builds on OAuth 2.1 (`@exortek/oauth2`), RFC 7519 (JWT), RFC 7517 (JWK).

## License

MIT © [ExorTek](https://github.com/ExorTek)
