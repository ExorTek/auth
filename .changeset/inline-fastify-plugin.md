---
'@exortek/apikey': patch
'@exortek/security': patch
'@exortek/session': patch
---

Replace `fastify-plugin` npm dependency with `@exortek/shared/fastify-plugin` — a built-in drop-in that covers skip-override, display-name, plugin-meta, version constraints, and encapsulate. Users no longer need to `npm i fastify-plugin` alongside fastify.
