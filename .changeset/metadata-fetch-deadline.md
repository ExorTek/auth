---
'@exortek/jwks': patch
'@exortek/oauth2': patch
'@exortek/oidc': patch
---

- Remote metadata fetches (JWKS, OAuth token / userinfo / discovery, OIDC end-session discovery) now keep one timeout over the request **and** the response body. Before, the timer stopped once the headers arrived, so an endpoint that stalled the body held the caller indefinitely.
- Response bodies are size-capped while they stream rather than after they are fully buffered. OIDC end-session discovery is capped at 1 MB and its per-issuer cache keeps at most 100 issuers.
- jwks: transport failures other than a timeout (DNS, connection reset) now surface as `FETCH_FAILED` instead of a raw `TypeError`.
