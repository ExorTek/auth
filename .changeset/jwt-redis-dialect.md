---
'@exortek/jwt': patch
---

Add `options.dialect` (`'ioredis' | 'node-redis'`) to `createRedisStore` so wrapped/proxied Redis clients can bypass constructor-name auto-detection.
