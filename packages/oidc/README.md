# @exortek/oidc

> OpenID Connect Core 1.0 for Node.js 22+ — the identity layer on top of **[`@exortek/oauth2`](../oauth2)**. Server-only, built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/oidc.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/oidc)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/oidc.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/oidc)](https://packagephobia.com/result?p=@exortek/oidc)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/oidc.svg?color=blue)](https://github.com/ExorTek/auth/blob/master/LICENSE)

> [!WARNING]
> **Pre-release scaffold (`0.0.0`).** The public surface —
> `createClient` / `createProvider`, the error catalogue, the subpath
> entries — is settled and validated, but the flow handlers
> (`createAuthUrl`, `handleCallback`, `discoveryHandler`,
> `userinfoHandler`) throw `NOT_IMPLEMENTED` until the endpoint pipeline
> lands. Not yet published to npm.

Where `@exortek/oauth2` already speaks OAuth 2.1 (and issues an opt-in
`id_token`), `@exortek/oidc` makes OpenID Connect the first-class shape:
the relying-party client enforces the `openid` scope and validates the
`id_token` end to end (`iss` / `aud` / `exp` / `nonce`, OIDC Core
§3.1.3.7), and the provider serves discovery + UserInfo on top of an
`@exortek/oauth2` authorization server.

## Why

- **`@exortek/oauth2`** gives you the OAuth 2.1 machinery — PKCE, `state`,
  `nonce`, DPoP, PAR, the authorization server. OIDC is the identity
  contract layered on it: who the user *is*, proven by a signed
  `id_token` and a UserInfo endpoint.
- Bolting OIDC onto a generic OAuth client by hand is where the subtle
  bugs live — a skipped `nonce` check, an unvalidated `aud`, trusting
  UserInfo `sub` over the `id_token` `sub`. This package refuses to let
  the caller skip them.

## Modules

| Import | Purpose |
|--------|---------|
| `@exortek/oidc` | Barrel — re-exports both halves + `ErrorCode` / `OidcError`. |
| `@exortek/oidc/client` | Relying-party (SSO) client — `createClient`. |
| `@exortek/oidc/provider` | OpenID Provider — `createProvider` (discovery + UserInfo + `id_token`). |

## Install

```bash
npm install @exortek/oidc
```

## Usage

```js
import { createProvider } from '@exortek/oidc/provider';
import { createClient } from '@exortek/oidc/client';

// OpenID Provider
const provider = createProvider({
  issuer: 'https://auth.myapp.com',
  jwks: keySet,
  store: myStore,
  claims: {
    supported: ['sub', 'email', 'name', 'picture', 'email_verified'],
    id_token: ['sub', 'email', 'name'],
    userinfo: ['email', 'name', 'picture'],
  },
});

app.get('/.well-known/openid-configuration', provider.discoveryHandler());
app.get('/userinfo', provider.userinfoHandler());

// Relying party (SSO)
const client = createClient({
  issuer: 'https://accounts.google.com',
  clientId: '...',
  clientSecret: '...',
  redirectUri: 'https://myapp.com/callback',
  scope: ['openid', 'email', 'profile'],
});

const { idToken, userinfo } = await client.handleCallback(req.query, {
  expectedState: session.state,
  expectedNonce: session.nonce,
});
```

## Why not just `@exortek/oauth2`?

Use `@exortek/oauth2` on its own when you need access-token authorization
and nothing more. Reach for `@exortek/oidc` the moment you need
*authentication* — a verified end-user identity — with the OIDC Core
guarantees enforced rather than reassembled per app.

## License

MIT © [ExorTek](https://github.com/ExorTek)
