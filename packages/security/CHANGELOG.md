# @exortek/security

## 1.0.0

### Major Changes

- Initial release. Framework-agnostic defensive HTTP layer for Node.js 22+ — CSRF, rate limiting, helmet-style headers,
  CORS, safe redirects, and 17 focused defensive helpers. Adapters for Fastify, Express, Hono, and Elysia.

  Highlights:

  - **csrf** — signed / unsigned / session-bound tokens; HMAC + timing-safe.
  - **rate-limit** — fixed / sliding / token-bucket / leaky-bucket + `multi` combinator + `withBan` escalation policy.
    Backends: memory (true LRU), Redis (atomic Lua, `defineCommand` EVALSHA on ioredis), custom.
  - **headers** — CSP with build-time source validation, HSTS with preload-eligibility guard, COOP/COEP/CORP, Referrer,
    Permissions, frameguard, noSniff, XSS-Protection.
  - **cors** — 6 origin flavours including sync/async predicates, preflight handling, `credentials: true` guard rails.
  - **redirect** — `safeRedirect` catches every classic open-redirect vector (protocol-relative, javascript:/data:
    schemes, userinfo tricks, control chars). Ships with `extractReturnUrl` and `isSameOrigin` for typical
    login-callback flows.
  - **17 helpers** — `getClientIp`, `bearer`, `checkOrigin`, `webhookVerify`, `sanitizeBody`, `sanitizeParams`,
    `safeJoin`, `sanitizeFilename`, `freezePrototypes`, `timeout`, `bodyLimit`, `honeypot`, `slowDown`, `safeJsonParse`,
    `constantTimeEqual`, `parseCspReport`, `cspNonce`.
  - **Adapters** — Fastify, Express, Hono, Elysia. Each ships a bundle (`securityMiddleware` / `securityPlugin`) AND
    per-concern middleware so you can pick just CORS or just rate-limit.
  - **Configurable rate-limit response headers** — `'legacy'` (default), `'draft'` (RFC 9331), `false`, or a per-field
    override.

  Runtime footprint: `node:crypto` + `node:path`, plus `fastify-plugin` (~3 KB) only when the `/fastify` subpath is
  imported. Every other framework is an optional peer.

  Ships with 238 tests (237 passing + 1 Redis integration gated on `REDIS_URL`). Pure JavaScript source, TypeScript
  types generated from JSDoc.
