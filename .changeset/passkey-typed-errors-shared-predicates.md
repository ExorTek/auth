---
'@exortek/passkey': minor
---

Every passkey failure now throws a typed `PasskeyError` with a branchable
`code`. The binary parsers (CBOR, ASN.1 DER, COSE, X.509, and the WebAuthn
authenticator/client-data readers) previously threw generic `Error`s, so a
malformed attestation or assertion surfaced from the public API with no `code` —
breaking the package's "branch on `err.code`" contract. They now carry proper
codes, including a new `ErrorCode.DECODE_ERROR` for low-level CBOR/DER decode
failures. Existing `try/catch` keeps working (`PasskeyError extends Error`); the
new capability is that `err.code` is now populated for parser failures too.

Internally, the 24 per-code `throwXxx` factory exports were removed in favour of
constructing `PasskeyError` directly (matching jwt / apikey / session), and the
argument checks now use `@exortek/shared/predicates`. No public-API surface was
removed — `index` only ever re-exported `PasskeyError` and `ErrorCode`.
