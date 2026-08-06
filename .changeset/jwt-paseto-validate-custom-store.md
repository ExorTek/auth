---
'@exortek/jwt': minor
'@exortek/paseto': minor
---

Validate custom store implementations at construction time. `createStore('custom', { impl })` previously accepted any object and returned it verbatim, so a store missing a required method surfaced only later as a `TypeError` deep inside a token operation. It now asserts the impl exposes the core registry contract — `add`, `has`, `get`, `delete`, `deleteAll` — and throws `INVALID_ARGUMENT` immediately when one is missing (`markUsed` stays optional, since only refresh-token rotation calls it).

Behaviour change: an incomplete custom store that happened to work — because the missing method was never exercised — is now rejected up front. Complete implementations are unaffected and are still returned verbatim (no wrapping).
