# `@exortek/oauth2` examples

Runnable, self-contained programs. Each reads its secrets from env vars —
set them, then `node <file>`.

> They import from the built package (`@exortek/oauth2`). From inside the
> monorepo run `yarn workspace @exortek/oauth2 build` first, or change the
> imports to `../src/…`.

## Using a provider preset

The 12 built-in presets (`@exortek/oauth2/providers/*`) — you bring the
client id / secret, they bring the endpoints + claim mapping.

| File                        | Framework | Shows                                                          |
| --------------------------- | --------- | ------------------------------------------------------------- |
| `login-express.mjs`         | Express   | `oauthLogin` handlers, web mode (Google + GitHub)             |
| `login-fastify.mjs`         | Fastify   | `oauthLoginPlugin`, web mode                                   |
| `login-api.mjs`             | Express   | `mode: 'api'` — client-held session for mobile / SPA / CLI    |
| `try-google-express.mjs`    | Express   | **Real Google, browser-clickable**, web **and** api in one page |
| `try-google-fastify.mjs`    | Fastify   | the same, on Fastify                                           |

```bash
# Browser-clickable, both modes — no Postman, no manual session/code carry:
GOOGLE_ID=…apps.googleusercontent.com GOOGLE_SECRET=GOCSPX-… \
  node examples/try-google-express.mjs      # then open http://localhost:5300
```

Add the printed redirect URIs to your Google OAuth client first.

## Creating a provider

For an IdP with no built-in preset — build one with `defineProvider`
(exactly how the presets are made).

| File                 | Shows                                                                     |
| -------------------- | ------------------------------------------------------------------------- |
| `custom-provider.mjs`| `defineProvider` + `discover: true` against any OIDC issuer (Keycloak / Auth0 / Okta / Zitadel / …) |
| `demo-local.mjs`     | a full custom provider (a stub IdP) **plus** the RP, both modes — runs end-to-end with **no external credentials** |

```bash
# Zero-credential end-to-end demo (stub IdP + RP, web + api):
node examples/demo-local.mjs               # then open http://localhost:5300

# Your own OIDC provider via discovery:
ISSUER=https://tenant.auth0.com CLIENT_ID=… CLIENT_SECRET=… \
  node examples/custom-provider.mjs
```

## Running an authorization server

| File                 | Shows                                                              |
| -------------------- | ----------------------------------------------------------------- |
| `server-express.mjs` | `createServer` — a minimal OAuth 2.1 AS (PKCE-required) on Express |

```bash
node examples/server-express.mjs
# metadata → http://localhost:4000/.well-known/oauth-authorization-server
```

> Note: `demo-local` / `try-google-*` use ports **5300/5400** so they don't
> collide with the docs dev server on 3000. Never commit a real client
> secret — pass it via env.
