---
'@exortek/apikey': patch
'@exortek/challenge': patch
'@exortek/crypto': patch
'@exortek/jwe': patch
'@exortek/jwk': patch
'@exortek/jwks': patch
'@exortek/jws': patch
'@exortek/jwt': patch
'@exortek/magic-link': patch
'@exortek/opaque': patch
'@exortek/otp': patch
'@exortek/paseto': patch
'@exortek/password': patch
'@exortek/security': patch
'@exortek/session': patch
---

Smaller bundles — the internal argument-guard helpers are now tree-shakeable.

Each package bundles the guard helpers it uses. They were previously built as
one object holding all fourteen, which a bundler cannot take apart, so every
package shipped all of them regardless of how many it called. They are now
individually importable, and each package pulls in only what it uses.

No API change: the errors, codes and messages raised by argument validation are
identical. Published bundles shrink by roughly 7-18% depending on the package.
