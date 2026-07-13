# Compliance mapping

Where `@exortek/*` packages sit against the standards commonly cited by
enterprise procurement, security architecture, and audit teams. Each
requirement is marked:

- ✅ **Covered** — the library defaults or an opt-in feature satisfies
  the control on its own.
- 🟡 **Assist** — the library provides the primitive; the caller has to
  wire it up correctly (usually a configuration decision).
- ❌ **Out of scope** — the control is above our layer (organisational
  policy, HR, physical security) or belongs to a package we haven't
  shipped yet.

## OWASP ASVS 4.0.3 — Application Security Verification Standard

Focused on the auth chapters (V2, V3, V4) and secrets storage (V6).

### V2 — Authentication

| §         | Requirement                                                                | Status | How                                                                                                    |
| --------- | -------------------------------------------------------------------------- | :----: | ------------------------------------------------------------------------------------------------------ |
| V2.1.1    | Passwords ≥ 8 chars, ≤ 64 not truncated                                    |   ✅   | `policy({ minLength })` default 12; `bcrypt.mode='prehash'` handles the 72-byte trap                   |
| V2.1.2    | Password length ≤ 128 accepted                                             |   ✅   | `MAX_PASSWORD_BYTES = 1024`; every byte counted                                                        |
| V2.1.5    | Change-password requires current password                                  |   🟡   | Caller's flow — use `password.verify(current, storedHash)` before accepting new                        |
| V2.1.7    | Passwords compared against known-breached corpus                           |   ✅   | `createHibpClient` (k-anonymity)                                                                       |
| V2.1.8    | Password strength meter available                                          |   ✅   | `password.strength()` — coarse 0-4 score + entropy                                                     |
| V2.1.9    | No composition rules unless justified                                      |   ✅   | `policy` defaults omit `requireClasses`; explicit opt-in                                               |
| V2.1.10   | No password rotation unless a compromise is suspected                      |   ✅   | Library ships history (opt-in), never enforces rotation cadence                                        |
| V2.1.11   | Copy/paste + password managers supported                                   |   ✅   | We accept anything up to 1024 bytes; NFKC normalized                                                   |
| V2.1.12   | Password hints not permitted                                               |   ✅   | Out of API surface                                                                                     |
| V2.2.1    | Anti-automation on auth endpoints                                          |   🟡   | Wire `@exortek/security`'s `rateLimit` on `/login` — see docs                                          |
| V2.2.2    | Weak auth countermeasures (rate limit, IP block)                           |   🟡   | Same as above                                                                                          |
| V2.2.3    | Notify on repeated auth failures                                           |   🟡   | Observability hook (roadmap)                                                                           |
| V2.3.1    | System-generated init passwords use CSPRNG + rotate                        |   ✅   | `password.generate` / `password.passphrase` on `crypto.randomBytes`                                    |
| V2.4.1    | Passwords salted with unique cryptographically random salt                 |   ✅   | Every hash function generates a fresh `crypto.randomBytes` salt                                        |
| V2.4.2    | Argon2id / scrypt / bcrypt / PBKDF2 with recommended params                |   ✅   | All four, OWASP 2024 defaults                                                                          |
| V2.4.4    | Additional secret used as part of hash (pepper)                            |   ✅   | `createPepper` with rotation                                                                           |
| V2.7.2    | OOB out-of-band tokens use CSPRNG, ≥ 6 digits                              |   ✅   | `otp.generateSecret` + `otp.totp` / `otp.hotp`                                                         |
| V2.7.3    | OOB tokens use timing-safe compare                                         |   ✅   | `otp.verifyTotp` uses `crypto.timingSafeEqual`                                                         |
| V2.7.4    | OOB single-use (replay defence)                                            |   ✅   | `otp.verifyTotp({ replay: { store } })` — atomic incr / CAS                                            |
| V2.8.1    | Time-based OTP compliant with RFC 6238                                     |   ✅   | RFC 6238 Appendix B vectors covered                                                                    |
| V2.8.2    | HOTP compliant with RFC 4226                                               |   ✅   | RFC 4226 Appendix D vectors covered                                                                    |
| V2.8.4    | HOTP counter resynchronisation                                             |   ✅   | `otp.resynchronize` (RFC 4226 §7.4)                                                                    |
| V2.9      | Cryptographic authenticators                                               |   🟡   | Passkey / WebAuthn package on roadmap                                                                  |
| V2.10.4   | Backup / recovery codes stored hashed                                      |   ✅   | `otp.backupCodes` — caller hashes via `password.scrypt.hash` before storing                            |

### V3 — Session Management

Session package is on the roadmap (`@exortek/session`). Current
libraries provide the primitives:

| §     | Requirement                                          | Status | How                                                                       |
| ----- | ---------------------------------------------------- | :----: | ------------------------------------------------------------------------- |
| V3.2  | Session token generation via CSPRNG                  |   ✅   | `crypto.random.token(bytes)`                                              |
| V3.4  | Cookie flags: Secure, HttpOnly, SameSite             |   🟡   | `security.csrfPlugin` sets these on its own cookie; app sets on session   |
| V3.5  | Token binding (`__Host-` prefix)                     |   ✅   | CSRF cookie uses `__Host-csrf`; session package will follow same pattern  |
| V3.7  | Server-side session invalidation on logout           |   🟡   | Session package roadmap                                                   |

### V4 — Access Control

Above our layer — authorisation is your app's concern. We provide the
building blocks (constant-time compare, timing-safe verify).

### V6 — Stored Cryptography

| §       | Requirement                                             | Status | How                                                                         |
| ------- | ------------------------------------------------------- | :----: | --------------------------------------------------------------------------- |
| V6.2.1  | Approved algorithms only                                |   ✅   | Every primitive is a NIST-approved / IETF-standardised algorithm            |
| V6.2.2  | Key management via KMS / HSM                            |   🟡   | Library accepts secrets as `Buffer | string` — caller supplies from KMS    |
| V6.2.3  | Keys rotated                                            |   ✅   | `unseal(token, [new, old])`, `createPepper({ secret: [new, old] })`, JWKS  |
| V6.2.4  | Algorithm agility (rehash on log-in)                    |   ✅   | `password.needsRehash` + cross-algo router                                  |
| V6.4.1  | AEAD ciphers, no CBC without HMAC                       |   ✅   | Only AES-256-GCM in `crypto.cipher`                                         |
| V6.4.2  | HMAC output ≥ 128 bits                                  |   ✅   | Minimum SHA-256 (256 bits)                                                  |

## NIST SP 800-63B — Digital Identity Guidelines

Applies at AAL2 (multi-factor). Selected controls:

| §         | Requirement                                                    | Status | How                                                                                  |
| --------- | -------------------------------------------------------------- | :----: | ------------------------------------------------------------------------------------ |
| 5.1.1.2   | Memorized secret verifier — min 8 chars, no composition rules  |   ✅   | `policy({ minLength: 8+ })`; classes off by default per NIST 2020 update             |
| 5.1.1.2   | Compare against list of known-breached values                  |   ✅   | `createHibpClient`                                                                   |
| 5.1.1.2   | Memorized secret NOT stored in plain text or reversibly encrypted |   ✅ | argon2id / scrypt / bcrypt / pbkdf2 — one-way KDFs only                              |
| 5.1.1.2   | Salted with unique per-user salt                               |   ✅   | Fresh salt every hash                                                                |
| 5.1.1.2   | Approved key derivation function with memory-hard preference   |   ✅   | Argon2id (memory-hard) is the recommended default                                    |
| 5.1.1.2   | Additional server-side secret (pepper) SHOULD be considered    |   ✅   | `createPepper`                                                                       |
| 5.1.1.2   | Rate limit consecutive failures                                |   🟡   | Wire `@exortek/security` rate limit on `/login`                                      |
| 5.1.4.2   | OOB authenticator, transmission via secure channel             |   🟡   | Caller's transport concern (TLS)                                                     |
| 5.1.5.2   | Single-factor OTP — RFC 4226 / 6238 compliant                  |   ✅   | Full RFC 4226 + 6238 coverage                                                        |
| 5.1.5.2   | OTP replay defence                                             |   ✅   | `otp.verifyTotp({ replay })` — atomic CAS                                            |
| 5.2.5     | Verifier compromise resistance — pepper / device binding      |   ✅   | `createPepper`                                                                       |
| 5.2.7     | Reauthentication cadence per AAL                                |   🟡   | Session package roadmap                                                              |
| 5.2.10    | Session bindings — key rotation on privilege escalation         |   🟡   | Session package roadmap                                                              |

## NIST SP 800-131A / FIPS 140-3 — Approved algorithms

Runtime restriction to FIPS-approved primitives is available via
`crypto` and `password` presets:

| Algorithm              | Approved (FIPS 140-3) | Available in `@exortek/*` | FIPS-only preset       |
| ---------------------- | :-------------------: | :-----------------------: | ---------------------- |
| **Password hashing**   |                       |                           |                        |
| PBKDF2-HMAC-SHA-256    |          ✅           |            ✅             | `presets.fips.pbkdf2`  |
| PBKDF2-HMAC-SHA-512    |          ✅           |            ✅             | `presets.fips.pbkdf2`  |
| Argon2id               |          ❌           |            ✅             | Rejected in FIPS mode  |
| scrypt                 |          ❌           |            ✅             | Rejected in FIPS mode  |
| bcrypt                 |          ❌           |            ✅             | Rejected in FIPS mode  |
| **Symmetric cipher**   |                       |                           |                        |
| AES-256-GCM            |          ✅           |            ✅             | Default in `crypto.cipher.seal` |
| **Hash**               |                       |                           |                        |
| SHA-256 / 384 / 512    |          ✅           |            ✅             | Default in every `crypto.hash` call |
| SHA-1                  |          🟡 legacy    |            ✅             | Available; OTP interop only |
| **MAC**                |                       |                           |                        |
| HMAC-SHA-256+          |          ✅           |            ✅             | Default HMAC output                |
| **Signature**          |                       |                           |                        |
| ECDSA (P-256/384/521)  |          ✅           |            ✅             | Available in `crypto.sign`         |
| Ed25519                |          ✅           |            ✅             | Available                          |
| RSA-PSS                |          ✅           |            ✅             | Available                          |
| **KDF**                |                       |                           |                        |
| HKDF-HMAC-SHA-256+     |          ✅           |            ✅             | Default in `crypto.hash.hkdf`      |

When Node is started with the `--enable-fips` flag on a FIPS-enabled
OpenSSL build, `@exortek/crypto` inherits the OpenSSL restrictions
automatically. Non-FIPS algorithms will throw at the OpenSSL layer.

## PCI-DSS 4.0

Selected requirements relevant to auth libraries:

| §        | Requirement                                                | Status | How                                                                                           |
| -------- | ---------------------------------------------------------- | :----: | --------------------------------------------------------------------------------------------- |
| 8.3.1    | Strong cryptography for stored passwords                   |   ✅   | argon2id / scrypt / bcrypt / pbkdf2                                                           |
| 8.3.6    | Passwords ≥ 12 chars mixed complexity                      |   ✅   | `policy({ minLength: 12, requireClasses: […] })`                                              |
| 8.3.7    | Password history (last ≥ 4)                                |   ✅   | `createHistory({ keepLast: 4+ })`                                                             |
| 8.3.9    | MFA on non-console access                                  |   ✅   | `@exortek/otp` for TOTP; passkey package on roadmap                                           |
| 8.3.10   | MFA replay protection                                      |   ✅   | `otp.verifyTotp({ replay })`                                                                  |
| 8.5.1    | System secrets encrypted at rest / not in source           |   🟡   | Caller loads from KMS / env; library never persists secrets                                   |
| 6.2.4    | Common attacks prevented — injection, XSS, CSRF            |   ✅   | `@exortek/security` — CSRF plugin, prototype-pollution defence, safe-redirect                 |

## SOC 2 CC6 — Logical and Physical Access

Above our layer for the most part. What we contribute:

- CC6.1 — logical access secured via strong authentication (`@exortek/otp` + `@exortek/password`)
- CC6.6 — auth failures + rate-limit hits emitted via observability hooks (roadmap)
- CC6.7 — key management via rotation-aware primitives (seal, sign-value, pepper)

## HIPAA / HITECH

Above our layer. The library holds up its end (approved crypto, no
insecure defaults) — the covered-entity audit surface is your app +
infrastructure.

## GDPR / Data Protection

Above our layer. Password hashes are considered personal data under
some interpretations; our KDFs are one-way and salted, which satisfies
the "pseudonymisation" bar in most authorities' interpretations. We
never transmit plaintext passwords over the network.

## Summary — what we ship today

- ✅ **NIST SP 800-63B AAL2** — memorized secret + OOB OTP paths
- ✅ **OWASP ASVS 4.0.3 V2 / V6** — password + storage controls
- ✅ **PCI-DSS 4.0 §8.3** — password strength, history, MFA
- ✅ **FIPS-compatible mode** — via presets and Node `--enable-fips`
- 🟡 **ASVS V3 session, V2.9 cryptographic authenticators** — coming
  with `@exortek/session` and `@exortek/passkey`
- 🟡 **Observability hooks** for SOC 2 / SIEM ingestion — roadmap

## Reading

- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- FIPS 140-3: https://csrc.nist.gov/publications/detail/fips/140/3/final
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
