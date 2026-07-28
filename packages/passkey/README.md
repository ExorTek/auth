# @exortek/passkey

> WebAuthn / FIDO2 server verification for Node.js 22+ — registration + authentication with an in-house CBOR + COSE + ASN.1 stack, all seven attestation formats, challenge store via `@exortek/challenge`. Zero non-`@exortek/*` runtime dependencies.

Scaffold — implementation lands in follow-up commits:

1. Internal util layer (CBOR, COSE, authData, clientData, minimal DER).
2. Registration flow (`begin` / `finish`, `none` + `packed`).
3. Authentication flow (`begin` / `finish`).
4. Attestation formats: `fido-u2f`, `tpm`, `android-key`, `android-safetynet`, `apple`.
5. README + web docs + example server.
6. Shipping checklist + 1.0.0.
