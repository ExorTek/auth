---
"@exortek/session": minor
---

Add `sessionStore.custom(impl)` (also exported as `customStore`) — wrap your own `SessionStore` implementation with validation (fails at construction time if a required method is missing) and transparent sync/async wrapping, instead of hand-assembling the interface yourself.
