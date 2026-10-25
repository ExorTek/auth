---
'@exortek/passkey': major
---

- `authentication.finish` binds the assertion to the stored credential and its owner: `credential.id` is required and must equal the assertion's credential id; with `expectedUserId`, `credential.userId` is required and must match; a stored `credential.userHandle` must equal the response's. Mismatches are the new `CREDENTIAL_MISMATCH`. Previously an attacker's own passkey could complete a victim's ceremony in apps that resolved the credential and the user separately.
- `requireTrustAnchor` admits only chains verified to an anchor — `none` and `packed` self attestation are no longer exempt.
- TPM attestation checks the AIK certificate's AAGUID extension; attestation chains honour `pathLenConstraint`; SafetyNet / packed subject checks compare parsed attributes (escaped commas no longer smuggle a CN / OU).
- MDS index entries carry `statusReports` and the latest `status`.
- COSE keys must match their algorithm's key type; duplicate byte-string CBOR map keys are rejected; authenticator extension keys can't swap a prototype.

**Migration:** pass `credential.id` (and `credential.userId` when you use `expectedUserId`) to `authentication.finish`. With `requireTrustAnchor`, expect `none` / self attestation to be refused.
