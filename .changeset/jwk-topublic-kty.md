---
'@exortek/jwk': patch
---

`toPublic` refuses key types other than RSA / EC / OKP instead of returning an unknown-kty JWK with its private members intact.
