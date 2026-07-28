---
"@exortek/magic-link": minor
---

Add `customStore(impl)` — wrap your own `MagicLinkStore` implementation with validation (fails at construction time if `put`/`getById`/`consume` are missing) and transparent sync/async wrapping. `incrRate`/`listByEmail`/`revokeByEmail` are passed through only when your implementation provides them.
