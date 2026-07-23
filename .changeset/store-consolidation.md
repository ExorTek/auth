---
"@exortek/challenge": patch
"@exortek/apikey": patch
"@exortek/session": patch
---

Consolidate duplicated store internals into @exortek/shared utilities
(redis-helpers, incr-store, record-store). No public API changes.

apikey: fix Redis store race condition where a concurrent update() could
silently un-revoke a key — revocations now use a tombstone key that
update() never touches.

apikey: fix memory store put() storing by reference instead of copying —
now consistent with getById()'s copy-on-read contract.
