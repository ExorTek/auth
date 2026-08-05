---
"@exortek/oauth2": major
---

Initial release. OAuth 2.1 for Node.js 22+ — the relying-party flow and a full authorization server, secure by default.

- `createOAuth` — the relying-party flow (PKCE S256, `state` / `nonce` generated and verified, exact `redirect_uri` + RFC 9207 `iss` matching) with 18 provider presets (`./providers/*`: google, github, microsoft, azure, discord, facebook, linkedin, spotify, twitch, apple, twitter, okta, gitlab, bitbucket, slack, reddit, amazon, salesforce).
- Login middleware for Express (`./express`) and Fastify (`./fastify`) — `web` (browser redirect, HMAC-signed or JWE-sealed flow-session cookie / store) and `api` (client-held session for mobile / SPA / CLI) modes; every platform from the backend.
- `createServer` — an OAuth 2.1 authorization server (`./server` + `./server/express` / `./server/fastify` adapters): authorize / token / revoke / introspect / PAR / device endpoints, RFC 8414 metadata, `jwtIssuer` (RFC 9068 `at+jwt`, default) + pluggable `pasetoIssuer`.
- Modern hardening — DPoP (RFC 9449, incl. the nonce challenge), PKCE (RFC 7636), PAR (RFC 9126), resource indicators (RFC 8707), RAR (RFC 9396), JAR/JARM (RFC 9101), `private_key_jwt` / `client_secret_jwt` (RFC 7523), mTLS (RFC 8705), token exchange (RFC 8693), device grant (RFC 8628), and the FAPI 2.0 profile. `verifyDpopForResource` for the resource-server half.
- In-memory and Redis-backed authorization-server stores behind one contract.
- Zero non-`@exortek/*` runtime dependencies.
