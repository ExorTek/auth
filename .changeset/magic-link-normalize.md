---
'@exortek/magic-link': major
---

- Email addresses are trimmed and lower-cased before indexing, rate limiting, hashing and lookup, so case variants no longer get separate rate-limit budgets or escape `revokeAllForEmail`.
- The memory store sweeps expired links and is bounded (`maxRecords`, default 100,000); its rate-limit counters are never evicted while live.

**Migration:** links issued to a mixed-case address before upgrading are not found by `listPendingForEmail` / `revokeAllForEmail`.
