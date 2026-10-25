---
'@exortek/apikey': minor
---

- `rehashApiKey` checks the presented secret against the stored hash before replacing it (anyone knowing a key id could overwrite its hash).
- `verifyApiKey` compares the secret before reporting `revoked` / `expired`, and accepts only the canonical spelling of a key (lowercase / I / O variants no longer verify).
