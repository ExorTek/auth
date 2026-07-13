---
'@exortek/otp': patch
---

- **`digits` JSDoc types widened to `6 | 7 | 8 | 9 | 10`** across
  `HotpVerifyOptions`, `TotpOptions`, `TotpVerifyOptions`, `ResyncOptions`,
  `ProvisioningOptions`, and `ParsedProvisioning`. Runtime already accepted
  6–10; the emitted `.d.ts` no longer flags `{ digits: 10 }` as a type
  error.
- **`remainingSeconds(period, timestamp, t0)`** now applies the epoch offset
  so the countdown lines up with `totp` / `verifyTotp` when a custom `t0`
  is in play (legacy SecurID migrations).
- **`decodeSecret(secret, { encoding })`** accepts an explicit encoding
  (`'base32' | 'base32padded' | 'hex' | 'raw'`), removing the ambiguity
  between hex-only inputs that happen to be valid base32.
- **TOTP replay guard uses atomic `incr(key, ttlMs)`** on the injected
  store, closing the TOCTOU window a `get`-then-`set` pair would leave
  open under concurrent verify calls.
