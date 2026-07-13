---
'@exortek/crypto': patch
---

- **HKDF `length` bound respects the chosen hash.** The 255 × hashLen limit is
  now computed against the real hash output size (SHA-256 → 8160, SHA-384 →
  12240, SHA-512 → 16320) instead of the hard-coded SHA-512 ceiling. Calls
  that would previously slip past validation and surface a raw Node
  `RangeError` are now rejected with `CryptoError(INVALID_ARGUMENT)`,
  matching the rest of the package's error contract.
- **`unseal` accepts a secret array for rotation.** Pass `[newest, …older]`
  as the second argument; each key is tried in order and the first that
  authenticates wins. Enables graceful key rotation without invalidating
  tokens minted under the previous secret. Backwards-compatible — a bare
  secret still works exactly as before.
