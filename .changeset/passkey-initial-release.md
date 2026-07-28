---
'@exortek/passkey': major
---

Initial release. WebAuthn Level 3 / FIDO2 CTAP2 server verification
for Node.js 22+, zero non-`@exortek/*` runtime dependencies,
server-only.

**Two flows, two calls each:**

- `registration.begin` → `registration.finish`
- `authentication.begin` → `authentication.finish`

**All seven WebAuthn L3 attestation formats:**

- `none` (§8.7)
- `packed` — self + full x5c, `OU=Authenticator Attestation`
  check, AAGUID cert-extension match (§8.2)
- `fido-u2f` — legacy U2F, implicit ES256/P-256 (§8.6)
- `apple` — anonymous attestation, nonce extension check (§8.8)
- `android-key` — StrongBox / Keystore, `attestationChallenge`
  in KeyDescription equals clientDataHash (§8.4)
- `android-safetynet` — JWS RS256, `attest.android.com` leaf CN,
  CTS profile match with opt-out knob, timestamp window (§8.5)
- `tpm` — TPM 2.0 TPMT_PUBLIC / TPMS_ATTEST parsing, AIK cert
  profile (TCG-KP-AIK EKU, CA:FALSE, empty subject, SAN) (§8.3)

**Extension I/O:**

- Registration: `credProps`, `largeBlob`, `prf`,
  `hmacCreateSecret`, `minPinLength`, `credentialProtectionPolicy`,
  `appidExclude`.
- Authentication: `largeBlob` (read/write), `prf` (eval +
  evalByCredential), `hmacGetSecret`, `appid`.
- Unknown keys pass through untouched.

**Modern WebAuthn L3 features:**

- Hints (`security-key` / `client-device` / `hybrid`).
- Related origins — `rpId` / `expectedRpId` accept string or array.
- Conditional UI mediation on `authentication.begin`.
- Backup-state policy dials: `requireBackedUp`, `requireBackupEligible`
  (accepted on both registration.finish AND authentication.finish).
- `allowCrossOriginCeremony` (default `false`) — reject
  `clientDataJSON.crossOrigin=true` unless the caller opts in.
- `attestationOptions?: Record<string, Record<string, unknown>>` on
  `registration.finish` — per-format knobs, keyed by format name
  (accepts hyphen-squashed keys too). Today lets the caller reach the
  `android-safetynet` verifier's `enforceCtsCheck`, `timestampWindowMs`
  and `now` options; new formats add knobs here without a signature
  change.

**Subpaths:**

- `@exortek/passkey/mds` — FIDO MDS3 blob verifier + AAGUID index
  builder (`verifyMdsBlob`, `buildAaguidIndex`).
- `@exortek/passkey/aaguid` — offline `AAGUID → { name }` lookup
  with a ~15-entry curated baseline.

**Trust:**

- Full X.509 chain verification with the GHSA-6hxq-p678-4hr2 guard
  (self-signed cert inside `x5c` cannot bypass RP-supplied anchors).
- Intermediate certs recognised as trust anchors (matches
  `@simplewebauthn/server` v13.0 behaviour).
- Default root CAs deliberately NOT bundled — vendor rotation
  makes pinning risky; callers supply their own `trustAnchors`.

**In-house cryptographic stack:**

- Minimal CBOR decoder (RFC 8949 subset — no tags, no indefinite
  length, strict duplicate-key rejection).
- COSE key parser (RFC 8152 + RFC 8230), both directions.
- Minimal ASN.1/DER walker for X.509 extension raw-bytes access
  (AAGUID OID, Apple nonce OID, KeyDescription OID, TCG-KP-AIK EKU).
- Node's built-in `X509Certificate` + `crypto` for signatures.

**Errors:** `PasskeyError` with 23 `ErrorCode` values — every code has
a throwing factory (`throwXxx`) that is exercised by tests, including
the four flag-policy codes (`USER_PRESENCE_REQUIRED`,
`USER_VERIFICATION_REQUIRED`, `BACKUP_ELIGIBLE_REQUIRED`,
`BACKED_UP_REQUIRED`) — no dead codes.

**Challenge lifecycle** delegated to `@exortek/challenge`
(single-use, TTL, method+step binding, replay guard via `IncrStore`).

**Tests:** 296 total, real ECDSA / RSA / Ed25519 signatures produced
via `node:crypto`, X.509 cert chains minted via openssl at test time
(skipped when openssl absent). Covers packed self + full mode,
none, fido-u2f, apple, android-key, android-safetynet, tpm; every
flag-policy `ErrorCode` fires end-to-end.

**Key hygiene:** RSA credential keys with a modulus below 2048 bits
are rejected at import (both COSE key import and TPM `pubArea` RSA
branch); packed leaf certificates are rewired against `basicConstraints
CA:TRUE` per §8.2 step 2.3.

**Deferred to 1.1:**

- `AuthorizationList` security-property checks inside `android-key`
  KeyDescription (require high-tag-number DER decoding).
- TPM `subjectAltName` deep parse for `tpmManufacturer` /
  `tpmModel` / `tpmVersion` directory attributes.
- Bundled default root CAs per format.
- `checkCertRevocation` optional CRL/OCSP hook.
