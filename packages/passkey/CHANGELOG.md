# @exortek/passkey

## 1.1.0

### Minor Changes

- ee78259: Every passkey failure now throws a typed `PasskeyError` with a branchable `code`. The binary parsers (CBOR,
  ASN.1 DER, COSE, X.509, and the WebAuthn authenticator/client-data readers) previously threw generic `Error`s, so a
  malformed attestation or assertion surfaced from the public API with no `code` — breaking the package's "branch on
  `err.code`" contract. They now carry proper codes, including a new `ErrorCode.DECODE_ERROR` for low-level CBOR/DER
  decode failures. Existing `try/catch` keeps working (`PasskeyError extends Error`); the new capability is that
  `err.code` is now populated for parser failures too.

  Internally, the 24 per-code `throwXxx` factory exports were removed in favour of constructing `PasskeyError` directly
  (matching jwt / apikey / session), and the argument checks now use `@exortek/shared/predicates`. No public-API surface
  was removed — `index` only ever re-exported `PasskeyError` and `ErrorCode`.

### Patch Changes

- 89aea87: Ship self-contained TypeScript declarations. Every package's emitted `.d.ts` referenced `@exortek/shared`
  (e.g. `import { BaseError } from '@exortek/shared/errors'`), but `@exortek/shared` is a private, never-published
  workspace package that is inlined into each bundle at build time. A TypeScript consumer therefore hit
  `Cannot find module '@exortek/shared/…'` (with `skipLibCheck` off) or silently degraded error-class types like
  `ApiKeyError` — losing its constructor signature and `.code` / `.message` — with `skipLibCheck` on.

  The build now runs a declaration-bundling pass (`rollup-plugin-dts`) after `tsc`, flattening each entry's `.d.ts` and
  inlining the `@exortek/shared` types so the shipped declarations are fully self-contained. Runtime deps and `node:*`
  stay external. No runtime or API change — types only.

- e9fc662: Publish sanctioned cross-package edges with a `workspace:^` range instead of `workspace:*`. The exact pin
  forced an exact `@exortek/crypto` (and, for passkey, `@exortek/challenge`) version into consumer trees, which could
  duplicate a copy of the dependency; the caret range dedupes to a single shared install. Aligns both manifests with the
  range policy in `AGENTS.md`.
- 3f6ce12: Correct and expand the built-in AAGUID → authenticator-name baseline (`@exortek/passkey/aaguid`), verified
  against the Passkey.dev community list.

  Two entries were wrong:

  - `d548826e-79b4-db40-a3d8-11116f7e8349` is **Bitwarden**, not "Google Password Manager (Android)" — a real Bitwarden
    passkey was reported under the wrong name (and no such Google AAGUID exists).
  - `d197a58d-4c07-4cff-8180-4e6c8fdd9c05` was labelled "Bitwarden" but is not Bitwarden's AAGUID; removed.

  Also renamed `fbfc3007-…` from "iCloud Keychain" to its current name **Apple Passwords**, and added six common
  providers: Bitwarden, Dashlane, Keeper, NordPass, Samsung Pass, Chrome on Mac, Edge on Mac.

- Updated dependencies [89aea87]
  - @exortek/challenge@1.1.3
  - @exortek/crypto@1.1.1

## 1.0.3

### Patch Changes

- b9e0647: Publish only the package-root README, CHANGELOG and LICENSE.

  The `files` list matched those names at any depth rather than just the root, so a nested document was published
  alongside them — `@exortek/oauth2` shipped its `examples/README.md`. The entries are now anchored to the package root.

- Updated dependencies [b827c5c]
- Updated dependencies [b9e0647]
- Updated dependencies [0a94f13]
- Updated dependencies [828f4ae]
  - @exortek/crypto@1.1.0
  - @exortek/challenge@1.1.2

## 1.0.2

### Patch Changes

- Updated dependencies [e53ae64]
  - @exortek/challenge@1.1.1
  - @exortek/crypto@1.0.9

## 1.0.1

### Patch Changes

- c8dcb42: Docs only. Align the README with the shared package template (add the tests / install-size / types badges,
  the Docs link and a Why section) and replace the box-drawing section dividers in the README examples with plain
  comments. No runtime code changed — the published 1.0.0 tarball only needed its README refreshed.

## 1.0.0

### Major Changes

- a6a3fe8: Initial release. WebAuthn Level 3 / FIDO2 CTAP2 server verification for Node.js 22+, zero non-`@exortek/*`
  runtime dependencies, server-only.

  **Two flows, two calls each:**

  - `registration.begin` → `registration.finish`
  - `authentication.begin` → `authentication.finish`

  **All seven WebAuthn L3 attestation formats:**

  - `none` (§8.7)
  - `packed` — self + full x5c, `OU=Authenticator Attestation` check, AAGUID cert-extension match (§8.2)
  - `fido-u2f` — legacy U2F, implicit ES256/P-256 (§8.6)
  - `apple` — anonymous attestation, nonce extension check (§8.8)
  - `android-key` — StrongBox / Keystore, `attestationChallenge` in KeyDescription equals clientDataHash (§8.4)
  - `android-safetynet` — JWS RS256, `attest.android.com` leaf CN, CTS profile match with opt-out knob, timestamp window
    (§8.5)
  - `tpm` — TPM 2.0 TPMT_PUBLIC / TPMS_ATTEST parsing, AIK cert profile (TCG-KP-AIK EKU, CA:FALSE, empty subject, SAN)
    (§8.3)

  **Extension I/O:**

  - Registration: `credProps`, `largeBlob`, `prf`, `hmacCreateSecret`, `minPinLength`, `credentialProtectionPolicy`,
    `appidExclude`.
  - Authentication: `largeBlob` (read/write), `prf` (eval + evalByCredential), `hmacGetSecret`, `appid`.
  - Unknown keys pass through untouched.

  **Modern WebAuthn L3 features:**

  - Hints (`security-key` / `client-device` / `hybrid`).
  - Related origins — `rpId` / `expectedRpId` accept string or array.
  - Conditional UI mediation on `authentication.begin`.
  - Backup-state policy dials: `requireBackedUp`, `requireBackupEligible` (accepted on both registration.finish AND
    authentication.finish).
  - `allowCrossOriginCeremony` (default `false`) — reject `clientDataJSON.crossOrigin=true` unless the caller opts in.
  - `attestationOptions?: Record<string, Record<string, unknown>>` on `registration.finish` — per-format knobs, keyed by
    format name (accepts hyphen-squashed keys too). Today lets the caller reach the `android-safetynet` verifier's
    `enforceCtsCheck`, `timestampWindowMs` and `now` options; new formats add knobs here without a signature change.

  **Subpaths:**

  - `@exortek/passkey/mds` — FIDO MDS3 blob verifier + AAGUID index builder (`verifyMdsBlob`, `buildAaguidIndex`).
  - `@exortek/passkey/aaguid` — offline `AAGUID → { name }` lookup with a ~15-entry curated baseline.

  **Trust:**

  - Full X.509 chain verification with the GHSA-6hxq-p678-4hr2 guard (self-signed cert inside `x5c` cannot bypass
    RP-supplied anchors).
  - Any certificate used as an issuer must be a CA (`basicConstraints cA=TRUE`, RFC 5280 §6.1.4) — stricter than
    `@simplewebauthn/server`.
  - Intermediate certs recognised as trust anchors (matches `@simplewebauthn/server` v13.0 behaviour).
  - Opt-in `requireTrustAnchor` on `registration.finish` — turns an unanchored chain-bearing attestation
    (`trustPath: 'no-anchor'`) into a hard `ATTESTATION_TRUST_ANCHOR_MISSING` (`none` / packed-self exempt).
  - `android-key` rejects a KeyDescription carrying `allApplications [600]` in either AuthorizationList (§8.4 step 4) —
    the key must be RP-scoped.
  - Both finish flows reject `response.id !== response.rawId` (parity with `@simplewebauthn/server`).
  - Default root CAs deliberately NOT bundled — vendor rotation makes pinning risky; callers supply their own
    `trustAnchors`.

  **In-house cryptographic stack:**

  - Minimal CBOR decoder (RFC 8949 subset — no tags, no indefinite length, strict duplicate-key rejection).
  - COSE key parser (RFC 8152 + RFC 8230), both directions.
  - Minimal ASN.1/DER walker for X.509 extension raw-bytes access (AAGUID OID, Apple nonce OID, KeyDescription OID,
    TCG-KP-AIK EKU).
  - Node's built-in `X509Certificate` + `crypto` for signatures.

  **Errors:** `PasskeyError` with 22 `ErrorCode` values — every code has a throwing factory (`throwXxx`) that is
  exercised by tests, including the four flag-policy codes (`USER_PRESENCE_REQUIRED`, `USER_VERIFICATION_REQUIRED`,
  `BACKUP_ELIGIBLE_REQUIRED`, `BACKED_UP_REQUIRED`) — no dead codes.

  **Challenge lifecycle** delegated to `@exortek/challenge` (single-use, TTL, method+step binding, replay guard via
  `IncrStore`).

  **Tests:** 309 total, real ECDSA / RSA / Ed25519 signatures produced via `node:crypto`, X.509 cert chains minted via
  openssl at test time (skipped when openssl absent). Covers packed self + full mode, none, fido-u2f, apple,
  android-key, android-safetynet, tpm; every flag-policy `ErrorCode` fires end-to-end; plus regression tests for the
  CBOR depth cap, DER length/high-tag parsing, the SafetyNet CN subdomain bypass, non-CA issuer rejection,
  `requireTrustAnchor`, and `android-key` `allApplications`.

  **Key hygiene:** RSA credential keys with a modulus below 2048 bits are rejected at import (both COSE key import and
  TPM `pubArea` RSA branch); packed leaf certificates are rewired against `basicConstraints CA:TRUE` per §8.2 step 2.3.

  **Deliberately out of scope for 1.0.0:**

  - Remaining `android-key` `AuthorizationList` fields beyond `allApplications` (`origin` = KM_ORIGIN_GENERATED,
    `purpose` ⊇ KM_PURPOSE_SIGN) — matching `@simplewebauthn/server`, which also checks only `allApplications`.
  - TPM `subjectAltName` deep parse for `tpmManufacturer` / `tpmModel` / `tpmVersion` directory attributes.
  - Bundled default root CAs per format.
  - Online revocation (CRL/OCSP) — kept out of the verify hot path; a cached, opt-in hook is the intended future shape.
