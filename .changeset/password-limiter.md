---
'@exortek/password': minor
---

- New `createLimiter({ concurrency, maxQueue })` limits how many password hashes run at once, so a login burst cannot take every libuv threadpool thread away from `fs` and DNS. Calls beyond the limit wait in a queue. Once `maxQueue` calls are waiting, further calls reject with the new `QUEUE_FULL` error code (HTTP 503).
