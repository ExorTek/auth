---
'@exortek/password': minor
'@exortek/otp': minor
'@exortek/security': minor
---

Remove 28 `ErrorCode` enum members that were defined but never thrown by any code path. These were speculative reservations — the actual failure modes use boolean returns or plain objects by design. READMEs updated to match.
