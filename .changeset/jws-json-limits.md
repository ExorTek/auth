---
'@exortek/jws': minor
---

- `verifyJson` enforces `maxTokenSize` (default 64 KiB for the serialized JSON) and `maxSignatures` (default 8) before decoding or verifying.
- A JWK that declares `alg`, `use` or `key_ops` is only used for that alg / signatures / that operation.
- JWK keys are imported once per object; HMAC signs with the KeyObject directly and ECDSA uses IEEE P1363 natively.
