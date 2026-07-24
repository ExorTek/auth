---
'@exortek/jwks': patch
---

Fix `cache:false` silently caching forever, harden remote fetch against SSRF (disable redirects, cap response at `maxResponseSize`), and fix abort-listener leak on long-lived resolvers by using `AbortSignal.any()`.
