---
'@exortek/password': patch
---

`pbkdf2.verify` now rejects PHC hashes whose iteration count exceeds a
10-million sanity ceiling instead of running the derivation. A poisoned
row with `i = 10^9` previously turned each login attempt into a
multi-second CPU stall; the ceiling short-circuits that path to
`false` while leaving every legitimate hash (OWASP-2024 targets 600k /
210k) well below the guard.
