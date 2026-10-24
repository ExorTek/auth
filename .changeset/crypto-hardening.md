---
'@exortek/crypto': major
---

Cipher and seal hardening.

- `seal` / `unseal` require every secret to be at least 32 bytes (`seal(x, '')` used to work).
- AEAD decryption (`decryptSymmetric`, `decryptFromString`, `decryptHybrid`) requires the full 16-byte tag and pins `authTagLength`; a truncated GCM tag (4 bytes verified before) is `DECRYPT_FAILED`. IV length is checked too.
- `unseal` and `decryptFromString` accept only the canonical unpadded base64url token — `t + '='`, whitespace or junk characters no longer decode to the same value.
- `unseal` rejects a non-finite or negative `clockSkew` (NaN used to disable expiry).
- `aad` with a non-AEAD algorithm (`aes-256-cbc`) is `INVALID_ARGUMENT` instead of being silently ignored.
- `encryptWithPassphrase` enforces the OWASP PBKDF2 floor (SHA-512 210,000; SHA-256 / SHA-384 600,000 iterations); decryption still honours the caller's value.
- `base58.decode` refuses input over 1024 characters unless `maxLength` is raised.
- `fingerprint` accepts shared (non-cyclic) references.

**Migration**

- Use ≥ 32-byte seal secrets (`crypto.randomBytes(32)`).
- Mint passphrase tokens with at least the floor iterations.
- Drop `aad` from CBC calls (or move to an AEAD algorithm).
