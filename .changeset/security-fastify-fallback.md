---
'@exortek/security': patch
---

Remove dead Fastify CSRF cookie fallback that would have emitted a malformed `Set-Cookie` header if the unreachable code path were ever reached.
