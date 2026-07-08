# @exortek/security

> Zero-dependency defensive HTTP layer for Node.js — built on `node:crypto`.

CSRF, rate limiting, helmet-style security headers, CORS, safe redirects,
and a dozen smaller helpers — one install, one API, no runtime deps.

Replaces the usual stack of `helmet` + `csrf-csrf` + `express-rate-limit` +
`express-slow-down` + `hpp` + `express-mongo-sanitize` + `cors` with a single
framework-agnostic package.

📖 **Docs:** [**auth.memet.dev/security**](https://auth.memet.dev/security)

## Install

```bash
npm  install @exortek/security
yarn add     @exortek/security
pnpm add     @exortek/security
```

Requires **Node.js 22 or newer**.

## Modules

| Subpath | Purpose |
| --- | --- |
| `@exortek/security/csrf` | signed / unsigned / session-bound CSRF tokens |
| `@exortek/security/rate-limit` | sliding, fixed, token-bucket, leaky-bucket + pluggable stores |
| `@exortek/security/headers` | CSP, HSTS, COOP/COEP/CORP, Referrer, Permissions, frameguard, noSniff |
| `@exortek/security/cors` | origin allowlist with preflight handling |
| `@exortek/security/redirect` | open-redirect guard |
| `@exortek/security/fastify` \| `/express` \| `/hono` \| `/elysia` | one-line all-in-one middleware |

The top-level `@exortek/security` re-exports everything; use subpaths for the
smallest tree-shaken bundle.

## License

MIT © ExorTek.
