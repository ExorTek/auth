---
"@exortek/jwks": patch
---

Fix `createLocalKeySet().handler()` throwing on Fastify — it called `res.writeHead`/`res.end` directly, which works for Express and raw Node but not Fastify, where the second handler argument is a `Reply` wrapper rather than the raw `ServerResponse`. Now unwraps `reply.raw` when present.
