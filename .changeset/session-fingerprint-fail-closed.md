---
'@exortek/session': major
---

**Breaking:** `verify()` now rejects tokens missing `fp` when `bindTo` is configured (fail-closed). Previously, tokens without a fingerprint silently bypassed binding checks. `impersonate()` now sets `fp` from the admin request, matching `issue()` and `rotate()`.

Existing sessions issued before `bindTo` was enabled will be rejected on next verify — users will need to re-authenticate.
