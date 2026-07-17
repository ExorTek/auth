---
'@exortek/session': minor
---

`deriveCsrfToken` now requires a secret of at least **32 bytes**, matching
the floor `@exortek/security`'s CSRF module has always enforced. Shorter
secrets throw `INVALID_ARGUMENT`. A 32-byte HMAC-SHA-256 secret is the
smallest value that resists offline brute-forcing of the derived token.

Callers passing shorter secrets (previously accepted without complaint)
must lengthen them — a `crypto.randomBytes(32).toString('base64url')`
value or any 32-plus-character string is sufficient.
