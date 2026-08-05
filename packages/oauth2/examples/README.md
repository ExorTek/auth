# `@exortek/oauth2` examples

Runnable, self-contained programs. Each reads its secrets from env vars —
set them, then `node <file>`.

| File                        | What it shows                                                        |
| --------------------------- | ------------------------------------------------------------------- |
| `login-express.mjs`         | Relying-party login (Google + GitHub) on Express — `oauthLogin`     |
| `login-fastify.mjs`         | The same login flow on Fastify — `oauthLoginPlugin`                  |
| `login-api.mjs`             | `mode: 'api'` — client-held session for mobile / SPA / CLI          |
| `server-express.mjs`        | A minimal OAuth 2.1 authorization server on Express — `createServer` |

```bash
# Relying party
GOOGLE_ID=… GOOGLE_SECRET=… GITHUB_ID=… GITHUB_SECRET=… SESSION_SECRET=… \
  node examples/login-express.mjs

# Authorization server
node examples/server-express.mjs
```

> These import from the built package (`@exortek/oauth2`). From inside the
> monorepo, `yarn workspace @exortek/oauth2 build` first, or adjust the
> imports to `../src/...`.
