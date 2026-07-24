---
'@exortek/password': patch
---

Make `history.isReused()` constant-time — always walks all `keepLast` hashes regardless of match position, removing the early-return timing side-channel.
