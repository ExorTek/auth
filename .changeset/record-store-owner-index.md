---
'@exortek/apikey': patch
'@exortek/magic-link': patch
'@exortek/oauth2': patch
---

- When a record is stored again under the same id with a different owner (`userId` / `email`), the previous owner no longer lists it, and per-owner bulk revocation (`revokeAllForUser`, `revokeByEmail`) no longer reaches it.
