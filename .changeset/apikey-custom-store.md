---
"@exortek/apikey": minor
---

Add `customStore(impl)` — wrap your own `ApiKeyStore` implementation with validation (fails at construction time if a required method is missing) and transparent sync/async wrapping, instead of hand-assembling the interface yourself.
