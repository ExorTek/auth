---
"@exortek/magic-link": patch
---

Fix _appendTokenParam stripping URL fragments from baseUrl before
appending the token query parameter — previously a #fragment in the
baseUrl would cause the token to land in the fragment and never reach
the server.

Fix memory store incrRate growing without bound — now capped at 10 000
entries via the shared IncrStore.
