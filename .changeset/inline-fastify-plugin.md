---
'@exortek/apikey': patch
'@exortek/security': patch
---

Drop `fastify-plugin` peer dependency — the two symbols it sets (`skip-override`, `fastify.display-name`) are now inlined. Users no longer need to `npm i fastify-plugin` alongside fastify.
