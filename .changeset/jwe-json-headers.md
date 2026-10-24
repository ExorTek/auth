---
'@exortek/jwe': major
---

- `decryptJson` requires the protected, shared-unprotected and per-recipient headers to be disjoint (RFC 7516 §7.2.1) and `crit` to be protected; it returns `protectedHeader` (authenticated members only), `unprotectedHeader` and the joint `header` separately. Previously an unprotected recipient header could override a protected value and was reported as protected.
- `encryptJson` refuses a parameter set both in `options.header` and on a recipient.
- `decryptJson` enforces `maxTokenSize` (default 64 KiB) and `maxRecipients` (default 8).
- A `zip` header is rejected instead of returning still-compressed bytes.

**Migration:** read `kid` and other per-recipient members from `header` or `unprotectedHeader`, not `protectedHeader`.
