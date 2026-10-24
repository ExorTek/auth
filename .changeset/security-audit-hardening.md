---
'@exortek/security': major
---

Rate-limit, proxy-trust and origin hardening.

**Security fixes**

- The Redis rate-limit store's `set()` dropped its TTL on node-redis, so `withBan` bans were never enforced there; it now dispatches per driver.
- `getClientIp` follows Express `trust proxy` semantics: the chain is `[socket peer, ...X-Forwarded-For right-to-left]` across every header line, `proxyCount: N` means `trust proxy: N` (it was one hop off), IPv4-mapped IPv6 is folded, `proxyCount` must be a non-negative integer, and `X-Real-IP` is read only when named in `headers`.
- Rate-limit middleware fails closed: a request with no derivable key shares one bucket (`onMissingKey: 'shared'`, default) or is refused (`'deny'`) instead of skipping the limit; IPv6 clients are keyed by their `/64` (`ipv6Subnet`); the never-read `trustProxy` option now throws.
- `webhookVerify` / `webhookVerifyStripe` reject an empty Buffer secret.
- `isSameOrigin` never treats opaque origins (`'null'`) as equal.
- CORS / `checkOrigin` RegExp patterns are stateless (`g` / `y` ignored), an un-anchored pattern warns once, and a CORS denial carries `Vary: Origin`.
- Fastify CSRF runs in `preHandler`, so a body form-field token is actually read.
- Token / leaky buckets no longer rewrite state on a denial (polling every millisecond inflated the refill ~1.6×).
- `sanitizeParams` drops `__proto__` / `constructor` / `prototype` keys.
- The CSRF middleware warns when the cookie name lacks the `__Host-` prefix.

**Migration**

- `getClientIp(req, { proxyCount })`: add 1 to keep the old behaviour, or better, set it to the number of proxies in front of Node (Express semantics).
- If you relied on `X-Real-IP`, pass `headers: ['x-real-ip']` explicitly (only behind a proxy that overwrites it).
- Remove `rateLimit.trustProxy` from middleware options and configure trust proxy on the framework.
- Unkeyed requests are now limited; pass `onMissingKey: 'deny'` to reject them instead.
- Existing IPv6 rate-limit counters re-key to `/64` prefixes on upgrade.
