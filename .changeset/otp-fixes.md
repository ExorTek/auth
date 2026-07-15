---
'@exortek/otp': patch
---

- `verifyTotp` no longer throws for `window` values 6–10 — the symmetric skew window is scanned through a shared core instead of being routed through `verifyHotp`'s forward-window guard.
- The secret is now base32-decoded once per verify/resync call instead of once per candidate counter (a `resynchronize` scan over 500 counters previously re-decoded the secret 500 times).
- Build hygiene: `build` / `clean` now also remove `tsconfig.tsbuildinfo` so `tsc --incremental` cannot leave stale `.d.ts` artifacts behind.
