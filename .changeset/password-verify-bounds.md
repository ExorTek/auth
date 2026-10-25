---
'@exortek/password': major
---

- `verify` bounds the cost a stored hash can demand: scrypt `128·N·r` ≤ 1 GiB and `128·N·r·p` ≤ 4 GiB, Argon2 `m` ≤ 1 GiB / `t` ≤ 10 / `p` ≤ 16, digests 16–64 bytes; scrypt / PBKDF2 return `false` instead of throwing on parameters node:crypto rejects.
- `pepper.wrap` normalizes the password (NFKC, NUL check, length cap) before the HMAC, like the unpeppered path; `wrapAll` also yields the legacy raw-input digest.
- The password length cap is applied before Unicode normalization.

**Migration:** if you verify peppered hashes with `wrap` (not `wrapAll`), switch to `wrapAll` until users with non-ASCII passwords have been rehashed — their pre-upgrade hashes match only the legacy candidate.
