---
'@exortek/session': patch
---

- Fastify adapter JSDoc referred to `reply.setSession` / `reply.clearSession`; the actual decorated methods are `reply.setSessionCookie` / `reply.clearSessionCookie`. JSDoc realigned so IDE hints match the runtime API.
- Build hygiene: `build` / `clean` now also remove `tsconfig.tsbuildinfo` so `tsc --incremental` cannot leave stale `.d.ts` artifacts behind.
