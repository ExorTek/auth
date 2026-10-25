---
'@exortek/challenge': major
---

- Verifying a `singleUse` challenge without `consume: true` fails with the new reason `consume_required` instead of passing (it used to verify any number of times).
- The memory store never evicts a live key when full — a new key throws (verify reports `store_unavailable`) instead of reopening another token's replay window.

**Migration:** pass `consume: true` and the store when verifying single-use challenges; size the memory store's `maxKeys` for peak load.
