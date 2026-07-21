# @exortek/security

> Framework-agnostic defensive HTTP layer for Node.js 22+ — built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/security.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/security)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/security.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/security)](https://packagephobia.com/result?p=@exortek/security)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/security.svg?color=blue)](./LICENSE)

CSRF, rate limiting, helmet-style headers, CORS, safe redirects, and 17 focused defensive helpers — one install replaces
`helmet` + `csrf-csrf` + `express-rate-limit` + `express-slow-down` + `cors` + `hpp` + `express-mongo-sanitize`. Adapters
for **Fastify**, **Express**, **Hono**, and **Elysia**.

📖 **Docs:** [**auth.memet.dev/security**](https://auth.memet.dev/security)

## Why

The defensive middleware most Node apps need is scattered across a dozen packages with mismatched APIs, drifting
maintainers, and subtle gaps (helmet has no CSP nonce helper, `csurf` was archived, `express- rate-limit`'s Redis story
is external). `@exortek/security` ships them once, correctly, framework-agnostically:

- **One API surface.** `csrf`, `rateLimit`, `headers`, `cors`, `safeRedirect` + 17 helpers — all pure functions. The
  framework adapters are a thin layer of glue on top.
- **Framework-agnostic.** Fastify, Express, Hono, Elysia. Each ships a bundle (`securityMiddleware`) **and** per-concern
  middleware so you can pick just CORS or just rate-limit if that's what you need.
- **Small footprint.** Runtime touches `node:crypto`, `node:path`, and — only when you import `/fastify` — a single ~3
  KB dep (`fastify-plugin`). Every framework itself is an **optional peer**.
- **JSDoc → `.d.ts`.** Pure JavaScript source, TypeScript types emitted at build. IDE hints without a `.ts` in sight.

## Install

```bash
npm  install @exortek/security
yarn add     @exortek/security
pnpm add     @exortek/security
```

Requires **Node.js 22 or newer**.

## Quick start

```js
import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import { securityPlugin } from '@exortek/security/fastify';
import { rateLimit } from '@exortek/security';

const app = Fastify();
await app.register(fastifyCookie);
await app.register(securityPlugin, {
  headers: {}, // secure defaults
  cors: { origin: ['https://app.example.com'], credentials: true },
  csrf: { secret: process.env.CSRF_SECRET }, // ≥ 32 bytes
  rateLimit: {
    limiter: rateLimit.sliding({
      requests: 100,
      window: '1m',
      store: rateLimit.stores.memory(),
    }),
  },
});
```

Same shape works on Express (`securityMiddleware`), Hono, and Elysia — see the docs.

## Modules

| Module                           | Purpose                                                                                                                                                                                                                                                              |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`csrf`](./src/csrf)             | signed / unsigned / session-bound CSRF tokens                                                                                                                                                                                                                        |
| [`rate-limit`](./src/rate-limit) | fixed / sliding / token-bucket / leaky-bucket + `multi` + `withBan` — over memory / Redis / custom stores                                                                                                                                                            |
| [`headers`](./src/headers)       | CSP (+ nonce), HSTS, COOP/COEP/CORP, Referrer, Permissions, frameguard, noSniff, XSS-Protection                                                                                                                                                                      |
| [`cors`](./src/cors)             | origin allowlist with preflight handling and async predicates                                                                                                                                                                                                        |
| [`redirect`](./src/redirect)     | open-redirect guard + `extractReturnUrl` + `isSameOrigin`                                                                                                                                                                                                            |
| [`helpers`](./src/helpers)       | `getClientIp` · `bearer` · `checkOrigin` · `webhookVerify` · `sanitizeBody` · `sanitizeParams` · `safeJoin` · `sanitizeFilename` · `freezePrototypes` · `timeout` · `bodyLimit` · `honeypot` · `slowDown` · `safeJsonParse` · `constantTimeEqual` · `parseCspReport` |
| middleware                       | `fastify` · `express` — each with `securityMiddleware` bundle **or** per-concern middleware                                                                                                                                                                          |

## Import styles

```js
// 1. Named at the top level — most ergonomic
import { cors, headers, safeRedirect, rateLimit } from '@exortek/security';

// 2. Named from a subpath — smallest bundle
import { cors } from '@exortek/security/cors';
import { rateLimit } from '@exortek/security/rate-limit';
import { safeRedirect } from '@exortek/security/redirect';

// 3. Framework middleware — one line for the whole stack
import { securityPlugin } from '@exortek/security/fastify';
import { securityMiddleware } from '@exortek/security/express';
```

## Error handling

Every recoverable failure throws `SecurityError` with a stable `ErrorCode`. Branch on the code, never on the message.

```js
import { SecurityError, ErrorCode, csrf } from '@exortek/security';

try {
  csrf.generate('too-short');
} catch (err) {
  if (!(err instanceof SecurityError)) throw err;
  if (err.code === ErrorCode.INVALID_ARGUMENT) {
    /* config bug */
  }
}
```

Codes: `INVALID_ARGUMENT`, `CSRF_MISSING`, `CSRF_MISMATCH`, `CSRF_MALFORMED`, `CSRF_TAMPERED`, `RATE_LIMITED`,
`ORIGIN_DENIED`, `REDIRECT_UNSAFE`, `PATH_TRAVERSAL`, `BODY_TOO_LARGE`, `REQUEST_TIMEOUT`, `WEBHOOK_INVALID`,
`HONEYPOT_TRIGGERED`.

## Highlights

- **CSRF that just works.** Signed double-submit by default — HMAC-based, timing-safe. Also session-bound (no
  per-request storage) and unsigned modes.
- **`rateLimit.multi(...)` + `withBan(...)`.** Layer 100/min AND 1000/hour AND after-5-denials-ban-for-1h without
  writing custom logic.
- **True LRU memory store.** Access refreshes recency, so a hot key can never evict itself under cap pressure (a subtle
  bypass in most in-process rate-limiters).
- **Async CORS predicates.** `origin: async (o) => db.hasOrigin(o)` — `check()` stays sync for static allowlists,
  becomes async only when it needs to.
- **`safeRedirect(next, { allowedHosts })`.** Catches every classic open-redirect vector: `//evil.com`, `javascript:`,
  `data:`, userinfo tricks, backslash tricks, protocol-relative, control chars.
- **`safeJsonParse(body)`.** JSON parse that refuses `__proto__` payloads — closes the prototype-pollution door at the
  request boundary. Pair with `freezePrototypes()` for global defence.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues & discussions:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](./LICENSE).
