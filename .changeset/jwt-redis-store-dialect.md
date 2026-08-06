---
'@exortek/jwt': patch
---

Fix the Redis store's client detection so the blacklist and refresh registry
work with both supported clients.

`createStore('redis', …)` identified an `ioredis` client by its constructor
name, which never matches a real instance — so every ioredis client took the
node-redis code path and `add()` sent the wrong `SET` argument form.
Separately, `markUsed()` ignored the detected dialect entirely and always used
the ioredis `eval` form, which node-redis accepts but executes with no keys.
Detection now probes the client's API surface, `markUsed()` branches like the
rest of the store, and `deleteAll()` seeds its `SCAN` cursor as a string
(node-redis requires this from v6, which the declared peer range admits).

If you previously worked around this by passing `dialect` explicitly, that
option still works and still takes precedence.
