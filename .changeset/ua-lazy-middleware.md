---
'@exortek/ua': patch
---

- The Express and Fastify middleware keep `req.ua` lazy: a section (`browser`, `os`, `device`, `engine`, `cpu`) is parsed only when it is first read, with Client Hints applied at that point. For a unique User-Agent where the handler reads one field, the cost drops from about 19 µs to 9 µs per request.
