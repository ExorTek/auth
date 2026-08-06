---
'@exortek/magic-link': patch
---

Fix two defects in the Redis store's `consume`.

`consume` and `revokeByEmail` issued their Lua call in the `ioredis` argument
form for every client, so both failed outright against node-redis — despite
the module documenting node-redis as a supported client. They now go through
the shared dialect-aware helper.

Separately, and on every client: the script treated a record whose
`consumedAt` was explicitly `null` as already consumed, because Redis's cjson
decodes a JSON null to a truthy value. A link stored that way could never be
redeemed. `create()` omits the field, so the default flow was unaffected, but
`consumedAt` is part of the documented record shape and normalising an absent
field to `null` is a common round-trip.
