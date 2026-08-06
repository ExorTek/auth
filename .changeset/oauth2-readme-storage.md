---
'@exortek/oauth2': patch
---

Document server storage, and correct the modules table.

The README never mentioned storage, so a reader following it deployed an
authorization server on in-memory stores and discovered the problem on the
second instance. It now covers the Redis-backed stores, which clients they
work with, and why memory is not a default to run behind a load balancer.

The modules table also named `mountOAuthLogin` as the fastify export — that
function is Express-only; the fastify subpath exports `oauthLogin` and
`oauthLoginPlugin`. The `./server` row listed three of its exports and omitted
the rest.
