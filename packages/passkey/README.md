# @exortek/passkey

> WebAuthn Level 3 / FIDO2 CTAP2 server verification for Node.js 22+ — registration + authentication with an in-house CBOR + COSE + ASN.1 stack, all seven attestation formats, WebAuthn hints, related origins, extension I/O (credProps / largeBlob / prf / hmac-secret / minPinLength / credProtect / appid), FIDO MDS3 verifier + offline AAGUID lookup. Zero non-`@exortek/*` runtime dependencies.

[![npm](https://img.shields.io/npm/v/@exortek/passkey.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/passkey)
[![tests](https://github.com/ExorTek/auth/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/passkey.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/passkey)](https://packagephobia.com/result?p=@exortek/passkey)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/passkey.svg?color=blue)](https://github.com/ExorTek/auth/blob/master/LICENSE)

📖 **Docs:** [**auth.memet.dev/passkey**](https://auth.memet.dev/passkey)

Server-only. For the browser side use `@simplewebauthn/browser` or `@github/webauthn-json`.

## Why

The server half of WebAuthn is deceptively hard: you hand-parse CBOR attestation objects, COSE public keys, and ASN.1 certificate chains, then verify seven attestation formats — each with its own quirks — while enforcing challenge single-use, origin, RP ID hash, the user-presence/verification/backup flag policy, counter monotonicity, and a trust-anchor story that a self-signed cert must not bypass (the exact CVE that hit a major library in 2026). `@exortek/passkey` ships all of it behind two calls per flow — `begin` then `finish` — on an in-house CBOR + COSE + ASN.1/DER + X.509 stack with no runtime dependency outside `@exortek/*`.

## Install

```bash
npm i @exortek/passkey
# or
yarn add @exortek/passkey
```

Node.js 22 LTS or newer.

## Quick start

```js
import { registration, authentication } from '@exortek/passkey';
import { createChallenge } from '@exortek/challenge'; // used by the store contract
import { memoryIncrStore } from '@exortek/challenge/stores'; // or your Redis store

const challengeStore = memoryIncrStore();
const CHALLENGE_SECRET = process.env.PASSKEY_CHALLENGE_SECRET;
const RP = { id: 'example.com', name: 'Example' };
const ORIGIN = 'https://example.com';

// REGISTRATION

// 1. Server mints options + a signed challenge token
app.post('/passkey/register/begin', async (req, res) => {
  const { options, challengeToken } = await registration.begin({
    rp: RP,
    user: { id: req.user.id, name: req.user.email, displayName: req.user.name },
    challengeSecret: CHALLENGE_SECRET,
    challengeStore,
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    hints: ['client-device'],
  });
  // Store challengeToken somewhere the client will hand back
  // (server-side session, encrypted cookie, whatever).
  req.session.passkey = { challengeToken };
  res.json(options);
});

// 2. Browser calls navigator.credentials.create(...), posts the response back
app.post('/passkey/register/finish', async (req, res) => {
  const { credential, aaguid, deviceType, backedUp, attestation } = await registration.finish({
    response: req.body,
    challengeToken: req.session.passkey.challengeToken,
    expectedRpId: RP.id,
    expectedOrigin: ORIGIN,
    challengeSecret: CHALLENGE_SECRET,
    challengeStore,
    expectedUserId: req.user.id,
    requireUserVerification: true,
  });
  // credential.id (base64url) is the primary key; store the record.
  await db.passkeys.insert({
    userId: req.user.id,
    credentialId: credential.id,
    publicKeyCose: [...credential.publicKeyCose.entries()], // serialisable Map
    algorithm: credential.algorithm,
    counter: credential.counter,
    transports: credential.transports,
    aaguid,
    deviceType,
    backedUp,
  });
  res.json({ ok: true });
});

// AUTHENTICATION

app.post('/passkey/login/begin', async (req, res) => {
  const { options, challengeToken } = await authentication.begin({
    rpId: RP.id,
    challengeSecret: CHALLENGE_SECRET,
    challengeStore,
    userVerification: 'required',
    conditional: true, // enables passkey autofill on supporting browsers
  });
  req.session.passkey = { challengeToken };
  res.json(options);
});

app.post('/passkey/login/finish', async (req, res) => {
  const row = await db.passkeys.findByCredentialId(req.body.id);
  const credential = {
    publicKeyCose: new Map(row.publicKeyCose),
    algorithm: row.algorithm,
    counter: row.counter,
  };
  const { newCounter, userHandle } = await authentication.finish({
    response: req.body,
    challengeToken: req.session.passkey.challengeToken,
    expectedRpId: RP.id,
    expectedOrigin: ORIGIN,
    challengeSecret: CHALLENGE_SECRET,
    challengeStore,
    credential,
    requireUserVerification: true,
  });
  await db.passkeys.updateCounter(row.credentialId, newCounter);
  req.session.userId = row.userId;
  res.json({ ok: true });
});
```

## Public API

Two flows, two calls each. Every function throws `PasskeyError` on failure — no `{ ok: false }` returns.

- `registration.begin({ rp, user, challengeSecret, challengeStore, ... })` → `{ options, challengeToken }`
- `registration.finish({ response, challengeToken, expectedRpId, expectedOrigin, ... })` → `{ credential, aaguid, deviceType, backedUp, attestation, extensionResults, rpId }`
- `authentication.begin({ rpId, challengeSecret, challengeStore, ... })` → `{ options, challengeToken }`
- `authentication.finish({ response, challengeToken, expectedRpId, expectedOrigin, credential, ... })` → `{ verified, newCounter, credentialId, userHandle, deviceType, backedUp, extensionResults, rpId }`

See `web/content/passkey/*.mdx` (or [auth.memet.dev/passkey](https://auth.memet.dev/passkey)) for the full option-by-option breakdown.

## Attestation formats

All seven WebAuthn L3 formats verified out of the box:

| Format               | Spec         | Notes                                                                     |
| -------------------- | ------------ | ------------------------------------------------------------------------- |
| `none`               | §8.7         | Empty attStmt                                                             |
| `packed`             | §8.2         | Self + full x5c; `OU=Authenticator Attestation` + AAGUID ext check        |
| `fido-u2f`           | §8.6         | Legacy U2F; implicit ES256 / P-256                                        |
| `apple`              | §8.8         | Anonymous attestation, nonce extension `1.2.840.113635.100.8.2`           |
| `android-key`        | §8.4         | KeyDescription extension, attestationChallenge check                      |
| `android-safetynet`  | §8.5         | JWS RS256, `attest.android.com` leaf CN, CTS + timestamp checks           |
| `tpm`                | §8.3         | TPM 2.0 TPMT_PUBLIC + TPMS_ATTEST parsing, AIK cert profile               |

Trust-anchor chain verification carries the GHSA-6hxq-p678-4hr2 fix — a self-signed cert inside `x5c` cannot bypass RP-supplied anchors. Bundled default root CAs are not shipped in 1.0.0 (vendor rotation makes pinning risky); pass `trustAnchors` per format if you want the chain check to enforce.

## Subpaths

- `@exortek/passkey/mds` — FIDO MDS3 blob verifier + AAGUID index builder.
- `@exortek/passkey/aaguid` — Offline AAGUID → device name lookup, ~15 well-known entries baseline.

## Extensions supported

Registration: `credProps`, `largeBlob`, `prf`, `hmacCreateSecret`, `minPinLength`, `credentialProtectionPolicy`, `appidExclude`.
Authentication: `largeBlob` (read/write), `prf` (eval + evalByCredential), `hmacGetSecret`, `appid`.
Unknown extension keys pass through unchanged.

## Errors

```js
import { PasskeyError, ErrorCode } from '@exortek/passkey';
```

Every code branches on `err.code` and maps to an HTTP status via `err.status`. Full catalogue: `INVALID_ARGUMENT`, `CHALLENGE_MISMATCH`, `CHALLENGE_EXPIRED`, `CHALLENGE_ALREADY_USED`, `CHALLENGE_INVALID`, `ORIGIN_MISMATCH`, `RP_ID_MISMATCH`, `CLIENT_DATA_INVALID`, `AUTH_DATA_INVALID`, `USER_VERIFICATION_REQUIRED`, `USER_PRESENCE_REQUIRED`, `BACKUP_ELIGIBLE_REQUIRED`, `BACKED_UP_REQUIRED`, `SIGNATURE_INVALID`, `COUNTER_ROLLBACK`, `PUBLIC_KEY_UNSUPPORTED`, `UNSUPPORTED_ALGORITHM`, `ATTESTATION_INVALID`, `ATTESTATION_TRUST_ANCHOR_MISSING`, `ATTESTATION_CERT_REVOKED`, `UNSUPPORTED_ATTESTATION_FORMAT`, `EXTENSION_INVALID`, `MDS_BLOB_INVALID`.

## Highlights

- All seven WebAuthn L3 attestation formats.
- WebAuthn L3 hints, related origins (`rpId` and `expectedRpId` accept string or string[]).
- Conditional UI mediation (`authentication.begin({ conditional: true })`).
- Backup-state policy dials (`requireBackedUp`, `requireBackupEligible`).
- SafetyNet CTS toggle, RSA-PSS, EdDSA/Ed25519, ES256/384/512.
- In-house CBOR + COSE + minimal ASN.1/DER — no `@peculiar/asn1-*`, no `cbor-x`, no transitive dep bloat.
- Challenge lifecycle via `@exortek/challenge` (single-use, TTL, method+step binding).
- Framework-agnostic — four functions, no HTTP handler assumptions.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues & discussions:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek — see [LICENSE](https://github.com/ExorTek/auth/blob/master/LICENSE).
