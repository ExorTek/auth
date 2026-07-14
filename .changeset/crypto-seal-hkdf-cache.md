---
'@exortek/crypto': patch
---

`seal`/`unseal` now cache the HKDF-derived encryption key when the
secret is a string, so the derivation runs once per string secret
instead of on every call. Session verify is the hot path here — this
cuts one HMAC-SHA-256 per token roundtrip.

Buffer / Uint8Array secrets are deliberately not cached: their
contents can be mutated (zeroised) after the fact, and an
identity-keyed cache would then serve a key for material that no
longer exists. Deployments that need caching should pass a string
secret.

The cache holds at most 8 entries; realistic rotation windows use 1-3
concurrent secrets so eviction is a safety valve, not a steady-state
path.
