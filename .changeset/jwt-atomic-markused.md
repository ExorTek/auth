---
'@exortek/jwt': minor
---

Add atomic `markUsed()` to memory and redis stores (Lua CAS on Redis). `tokenPair.rotate()` now uses it for cross-process safe reuse detection. Custom stores without `markUsed` fall back to the existing in-process mutex.
