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
'@exortek/oauth2': patch
'@exortek/opaque': patch
'@exortek/otp': patch
'@exortek/paseto': patch
'@exortek/passkey': patch
'@exortek/password': patch
'@exortek/security': patch
'@exortek/session': patch
'@exortek/ua': patch
---

Publish only the package-root README, CHANGELOG and LICENSE.

The `files` list matched those names at any depth rather than just the root, so
a nested document was published alongside them — `@exortek/oauth2` shipped its
`examples/README.md`. The entries are now anchored to the package root.
