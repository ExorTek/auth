---
'@exortek/apikey': patch
'@exortek/challenge': patch
'@exortek/jwe': patch
'@exortek/jwks': patch
'@exortek/jwt': patch
'@exortek/magic-link': patch
'@exortek/oauth2': patch
'@exortek/oidc': patch
'@exortek/opaque': patch
'@exortek/paseto': patch
'@exortek/security': patch
'@exortek/session': patch
---

- Duration strings whose unit is the name of an `Object.prototype` member (for example `'1constructor'`) now throw instead of resolving to `NaN`.
