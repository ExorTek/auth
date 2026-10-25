---
'@exortek/otp': patch
---

The TOTP replay marker now lasts until the matched counter leaves the acceptance window; a code matched ahead of the window centre could previously be replayed after the marker expired.
