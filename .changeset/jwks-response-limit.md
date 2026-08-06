---
'@exortek/jwks': patch
---

Enforce `maxResponseSize` while the JWKS response is read, rather than after.

The limit was checked against the `Content-Length` header and then again once
the body had been read in full. A response that omits the header — any chunked
reply — skipped the first check, so the entire body was already buffered by the
time the second one ran and the limit had no effect on what was allocated. The
body is now read incrementally and abandoned as soon as it crosses the limit.
