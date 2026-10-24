---
'@exortek/jwks': patch
---

- The remote resolver's `alg` cross-check now also applies to a key found by a kid-miss refetch.
- Local key sets import each key once instead of on every resolve.
