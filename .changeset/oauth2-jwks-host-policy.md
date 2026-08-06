---
'@exortek/oauth2': minor
'@exortek/jwks': minor
---

Let a deployment constrain which hosts the authorization server will fetch a
client's `jwks_uri` from.

A client's `jwks_uri` is client-supplied, and the server fetches it when
verifying `private_key_jwt` client assertions and JAR request objects. Under
dynamic client registration the value is chosen by whoever registered, so the
destination is worth constraining.

`createServer` accepts `security.allowJwksHost`, a predicate receiving the
hostname and parsed URL; returning `false` refuses the URI. `createRemoteJWKS`
gains the same hook as `allowHost`. Both are optional and unset by default —
existing behaviour is unchanged.

Recommended wherever `registration` is enabled.
