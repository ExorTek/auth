---
'@exortek/security': patch
---

- **`sanitizeBody` blocks prototype poisoning unconditionally.** Keys named
  `__proto__`, `constructor`, and `prototype` are always dropped, and
  surviving entries are written with `Object.defineProperty` as own
  properties — the prototype chain of the sanitised output is inert even
  under crafted payloads.
- **Hono / Elysia rate-limit no longer trusts `X-Forwarded-For` by
  default.** Without a proxy in front, `X-Forwarded-For` is
  client-controlled — trusting it lets an attacker rotate the header to
  mint unlimited rate-limit buckets. The adapters now fall back to the
  socket peer address unless the caller opts in with
  `rateLimit: { trustProxy: true }` or supplies a `keyGenerator` that
  reads their platform's trusted header (`CF-Connecting-IP`,
  `Fastly-Client-IP`, …). Fastify and Express were already safe
  (`req.ip` respects each framework's own `trustProxy` setting).
- **`slowDown` DoS caveat documented.** The helper holds each throttled
  request open on `setTimeout`, so under sustained abuse the delay
  itself ties up sockets and event-loop slots. The JSDoc and web docs
  now spell out the mitigations (`http.Server.maxConnections`,
  `limit_conn`, chaining behind a hard rejecting limiter).
