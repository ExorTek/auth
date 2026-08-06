---
'@exortek/paseto': patch
---

Fix refresh-family revocation against node-redis v6.

The Redis store walked the keyspace with `SCAN`, seeding the cursor as a
number on the node-redis branch. node-redis typed cursors as numbers through
v5 but requires a string from v6 onward, and the declared peer range
(`redis >=4.0.0`) admits v6 — so `deleteAll`, and therefore the family
revocation that runs on detected refresh-token reuse, failed there. The cursor
is now a string for both clients, which Redis accepts either way.
