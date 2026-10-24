---
'@exortek/oauth2': major
---

Authorization-server and RP hardening. Several defaults are stricter, so this is a major release.

**Security fixes**

- Every grant caps the granted scope at the client's registered `scope` ∩ the server's `scopes`; previously a client's own `scope` replaced the server list, and the device endpoint did not validate scope at all.
- Dynamic registration only accepts `grant_types` from `registration.allowedGrants` (default `authorization_code` + `refresh_token`), scopes the server advertises, and auth methods from `registration.allowedAuthMethods` (default: every non-mTLS method). Redirect URIs must be `https`, loopback `http`, or a reverse-domain private-use scheme, with no fragment.
- `?_fromPar=1` no longer bypasses a PAR requirement; `request_uri` must be redeemed with the `client_id` that pushed it, and a request object pushed to PAR is verified at push time.
- `tls_client_auth` requires a chain the TLS layer verified (`socket.authorized`) and compares the subject DN attribute by attribute.
- Rotated refresh tokens keep the family's expiry (they previously never expired), rotation is a compare-and-set (a lost race revokes the family), and a narrowed refresh request no longer narrows the successor token.
- Token exchange checks that the subject token was issued to / for the exchanging client (`client_id`, `aud` or `may_act`), requires the bound key for a DPoP- or certificate-bound subject token, and only exchanges for targets in `tokenExchange.audiences`.
- Device codes keep their original expiry while polled and are redeemed exactly once.
- A replayed authorization code revokes the refresh family it produced; introspection requires a confidential client.
- Client JWKS resolvers are cached per server; with registration enabled, `jwks_uri` hosts on loopback / private / link-local addresses are refused unless `security.allowJwksHost` says otherwise.
- RP: reserved authorize params (`state`, `nonce`, `redirect_uri`, `scope`, PKCE, …) can no longer be overridden via `params`; api-mode login requires a flow-session secret and every such secret must be ≥ 32 bytes; an OIDC provider must declare an `issuer`; `EMAIL_UNVERIFIED` also fires when a provider omits `email_verified`.

**New**

- `stores.replay` (any `incr(key, ttlMs)` store) and `createRedisReplayStore(redis)` share DPoP / client-assertion / request-object jti replay checks across nodes; `verifyDpopForResource` accepts a `replayStore`.
- DPoP nonces are stateless; set the same `security.dpop.nonceSecret` (≥ 32 bytes) on every node.
- `DeviceStore.redeem()` (optional) for atomic device-code redemption; `introspection.allowPublicClients`.

**Migration**

- List every scope a client may receive in the server's `scopes`.
- If self-registered clients need `client_credentials`, device or token exchange, add them to `registration.allowedGrants`.
- Replace plain-`http` (non-loopback) or single-word custom-scheme redirect URIs.
- Add `tokenExchange: { audiences: [...] }` if you exchange tokens for a `resource` / `audience`.
- On a bare `node:http` listener with `tls_client_auth`, pass `clientCertificateAuthorized: socket.authorized` in the request descriptor.
- Custom refresh stores: `rotate` should resolve `false` when the token was already rotated (resolving nothing keeps the old behaviour).
- Behind a load balancer with `dpop.nonce: true`, configure `security.dpop.nonceSecret`; add `stores.replay` for cross-node replay checks.
- RP: give api-mode login a `secret`, make every flow-session secret ≥ 32 bytes, add an `issuer` to custom OIDC providers, and stop passing reserved keys in `authorize(..., { params })`.
