# @exortek/password

## 1.1.0

### Minor Changes

- 48f1b5e: Remove 28 `ErrorCode` enum members that were defined but never thrown by any code path. These were
  speculative reservations — the actual failure modes use boolean returns or plain objects by design. READMEs updated to
  match.

### Patch Changes

- d28fbfb: Make `history.isReused()` constant-time — always walks all `keepLast` hashes regardless of match position,
  removing the early-return timing side-channel.

## 1.0.4

### Patch Changes

- `scrypt.verify` and `bcrypt.verify` now cap the cost parameters they read out of the stored PHC / bcrypt string,
  matching the `MAX_VERIFY_ITERATIONS` pattern already used in `pbkdf2.verify` (1.0.2). A poisoned hash — reachable via
  account-recovery import, migration tooling, or any attacker-influenced write path — could previously turn every login
  attempt into a process-wide CPU/memory DoS: `scrypt.verify` accepted `ln` up to 31 (~2 TB allocation), `bcrypt.verify`
  accepted `rounds` up to 31 (~2^31 synchronous Blowfish key-schedule iterations). Caps are independent of the hash-side
  ceiling: `scrypt.verify` rejects `ln > 24` and `r`/`p > 32`; `bcrypt.verify` rejects `rounds > 20`. Both return
  `false` instead of throwing — consistent with the existing verify-side untrusted-input contract. Every legitimate hash
  produced with OWASP-2024 defaults sits well under the guards.

## 1.0.3

### Patch Changes

- Internal refactor: errors extend the shared `BaseError`; `createPepper` config validated through
  `@exortek/shared/validate`; timing-safe compare, byte helpers, RFC 4648 §4 base64 codec, and rejection-sampling
  primitives delegate to `@exortek/shared`; argument guards bind through `@exortek/shared/asserts` via
  `internal/guards.js`. No public API change.

## 1.0.2

### Patch Changes

- bb21b15: `pbkdf2.verify` now rejects PHC hashes whose iteration count exceeds a 10-million sanity ceiling instead of
  running the derivation. A poisoned row with `i = 10^9` previously turned each login attempt into a multi-second CPU
  stall; the ceiling short-circuits that path to `false` while leaving every legitimate hash (OWASP-2024 targets 600k /
  210k) well below the guard.

## 1.0.1

### Patch Changes

- a0e4300: - **Fix TypeScript type resolution for the algorithm subpaths.**
  `@exortek/password/{scrypt,pbkdf2,argon2,bcrypt}` pointed their `types` field at `./dist/<name>.d.ts`, but `tsc`
  mirrors the source tree and actually emits at `./dist/algorithms/<name>.d.ts`. TS consumers of these subpaths got
  `Could not find a declaration file` — runtime worked, types didn't. `exports` now points at the correct nested paths.
  - Remove a dead `if (rounds < 10)` branch in `bcrypt.assertRounds` — the intended soft-warn was never implemented,
    only a comment sat there.
  - Build hygiene: `build` / `clean` now also remove `tsconfig.tsbuildinfo` so `tsc --incremental` cannot leave stale
    `.d.ts` artifacts behind.

## 1.0.0

### Major Changes

- d39d515: Initial release of `@exortek/password`.

  Four password-hashing algorithms under one coherent API — **argon2id**, **scrypt**, **bcrypt**, **PBKDF2** — with
  automatic algorithm routing on verify (bcrypt's `$2b$` format and PHC prefixes all dispatched by a single umbrella
  `password.verify`). OWASP 2024 defaults across the board, PHC string output for portability, and self-describing
  hashes so migration between algorithms is a `verify → hash → store` triangle away.

  Also ships every password-adjacent helper a backend needs:

  - **`constantTimeVerify`** — closes the classic user-enumeration side channel by running a decoy verify when the
    account doesn't exist.
  - **`needsRehash`** — cross-algorithm parameter-drift check for silent login-time migration.
  - **`strength`** — coarse 0-4 score with entropy and structural weakness flags; runs offline, no dictionary bundled.
  - **`generate`** / **`passphrase`** — CSPRNG rejection-sampling generators (no modulo bias) with Crockford / hex /
    URL-safe alphabets and a diceware-style word list.
  - **`policy`** / **`assertPolicy`** — structured rule-based validator with `denyList`, `userInfo` substring checks,
    `requireMinScore`.
  - **`createPepper`** — HMAC-based server-side pepper with **multi-secret rotation** (`wrap` for newest, `wrapAll` for
    verify-list).
  - **`createHistory`** — stateless "don't reuse the last N" helper that routes through the umbrella verify
    (mixed-algorithm history works).
  - **`createHibpClient`** — k-anonymity Have-I-Been-Pwned lookup with `Add-Padding`, injectable fetch, and `failOpen`
    for signup flows.
  - **`presets`** — `owasp2024` / `sensitive` / `interactive` / `fips` parameter bundles.
  - **PHC codec** — `parseHash` / `serialiseHash` for argon2, scrypt, pbkdf2 plus `$2b$` bcrypt.

  Peer dependencies (`argon2`, `bcryptjs`) are **optional** — the base package works with just `node:crypto` for
  scrypt + pbkdf2. Install a peer only when you need that specific algorithm; the runtime throws `MISSING_PEER_DEP` with
  an actionable install command if it isn't present.

  **135 unit tests** including PHC round-trip fuzz, RFC KAT vectors, concurrent-verify race, cross-algorithm routing,
  timing-defence smoke, and pepper-rotation flow.
