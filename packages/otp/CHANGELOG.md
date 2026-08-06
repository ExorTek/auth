# @exortek/otp

## 1.1.4

### Patch Changes

- 89aea87: Ship self-contained TypeScript declarations. Every package's emitted `.d.ts` referenced `@exortek/shared`
  (e.g. `import { BaseError } from '@exortek/shared/errors'`), but `@exortek/shared` is a private, never-published
  workspace package that is inlined into each bundle at build time. A TypeScript consumer therefore hit
  `Cannot find module '@exortek/shared/…'` (with `skipLibCheck` off) or silently degraded error-class types like
  `ApiKeyError` — losing its constructor signature and `.code` / `.message` — with `skipLibCheck` on.

  The build now runs a declaration-bundling pass (`rollup-plugin-dts`) after `tsc`, flattening each entry's `.d.ts` and
  inlining the `@exortek/shared` types so the shipped declarations are fully self-contained. Runtime deps and `node:*`
  stay external. No runtime or API change — types only.

## 1.1.3

### Patch Changes

- b9e0647: Publish only the package-root README, CHANGELOG and LICENSE.

  The `files` list matched those names at any depth rather than just the root, so a nested document was published
  alongside them — `@exortek/oauth2` shipped its `examples/README.md`. The entries are now anchored to the package root.

- 0a94f13: Smaller bundles — the internal argument-guard helpers are now tree-shakeable.

  Each package bundles the guard helpers it uses. They were previously built as one object holding all fourteen, which a
  bundler cannot take apart, so every package shipped all of them regardless of how many it called. They are now
  individually importable, and each package pulls in only what it uses.

  No API change: the errors, codes and messages raised by argument validation are identical. Published bundles shrink by
  roughly 7-18% depending on the package.

## 1.1.2

### Patch Changes

- e53ae64: Fix polynomial-ReDoS (quadratic regex backtracking) surfaced by CodeQL, plus small code-quality fixes.
  Bundled `@exortek/shared` utilities (base32, base64, duration) are inlined into the packages listed above, so each
  ships the fix.

  - Replace `/=+$/` trailing-padding strips (base32 / base64 decode, OTP provisioning URI) with linear scans —
    `"=".repeat(n) + "x"` was O(n²).
  - Rework the duration parser regex so surrounding whitespace can no longer cause O(n²) matching (trim first, single
    interior `\s*`).
  - Strip trailing spaces/dots in filename sanitisation with a linear scan — upload filenames are attacker-controlled.
  - Cap email length before the regex in magic-link.
  - Thread the JWT decode label into error messages (removes dead arguments and gives failures which segment broke).
  - Drop a duplicate character in a UA browser-detection regex character class.

  DoS-hardening and hygiene only — no API or behavioural change for valid input.

## 1.1.1

### Patch Changes

- 689cf87: Remove workspace-only `devDependencies` from published package.json — `@exortek/shared` no longer appears as
  `"0.0.0"` on the npm registry.

## 1.1.0

### Minor Changes

- 48f1b5e: Remove 28 `ErrorCode` enum members that were defined but never thrown by any code path. These were
  speculative reservations — the actual failure modes use boolean returns or plain objects by design. READMEs updated to
  match.

## 1.0.2

### Patch Changes

- Internal refactor: errors + base32 re-export via `@exortek/shared`; backup-code alphabet from
  `@exortek/shared/crockford`; timing-safe compare + rejection sampling delegated to shared; `backupCodes` options
  validated through `@exortek/shared/validate`; argument guards bind through `@exortek/shared/asserts` via
  `internal/guards.js`. No public API change.
- docs: `verifyTotp` README now carries a prominent callout that codes remain replayable within the acceptance window
  (~90s at defaults) unless `options.replay` is wired. First-time integrators calling `verifyTotp(code, secret)` likely
  assume single-use semantics they don't actually get without the replay store; the deep-dive "Replay defense" section
  existed but nothing at the API description pointed there. No behavior change.

## 1.0.1

### Patch Changes

- f9971f1: - `verifyTotp` no longer throws for `window` values 6–10 — the symmetric skew window is scanned through a
  shared core instead of being routed through `verifyHotp`'s forward-window guard.
  - The secret is now base32-decoded once per verify/resync call instead of once per candidate counter (a
    `resynchronize` scan over 500 counters previously re-decoded the secret 500 times).
  - Build hygiene: `build` / `clean` now also remove `tsconfig.tsbuildinfo` so `tsc --incremental` cannot leave stale
    `.d.ts` artifacts behind.

## 1.0.0

### Major Changes

- Initial release. RFC 4226 HOTP + RFC 6238 TOTP for Node.js 22+ with secure defaults, tunable window / algorithm /
  digits, and everything you need around the primitives.

  Highlights:

  - **TOTP** — configurable period, digits, algorithm, and `t0` epoch offset. Verify with a tunable drift window (±N
    periods) — matches Google Authenticator's internal tolerance by default.
  - **HOTP** — counter-based cousin plus the RFC 4226 §7.4 **resync protocol** (`resynchronize`) for drifted hardware
    tokens.
  - **Provisioning** — `provisioningUri` emits `otpauth://` URIs compatible with Google Authenticator, Microsoft
    Authenticator, Authy, 1Password, Bitwarden, Aegis, Yubico Authenticator, and every other mainstream 2FA app. Refuses
    `SHA-224` / `SHA-384` in URIs (spec doesn't ship them) but accepts them in `hotp` / `totp` for server-server flows.
  - **Enrollment sugar** — `enroll({ label, issuer })` mints the secret, builds the URI, and issues backup codes in one
    call. Round-trippable via `parseProvisioningUri`.
  - **Backup codes** — unambiguous Crockford alphabet by default (no 0/O/1/I/L), plus 5 ready-made presets (`numeric`,
    `long`, `hex`, `short`, `crockford`). `verifyBackupCode(input, list)` walks the stored list in constant time.
  - **Replay defense** — opt-in `replay` option on `verifyTotp` makes each code single-use per counter per key. Works
    with any store shaped like `@exortek/security`'s rate-limit stores (memory / Redis / custom).
  - **Digit range 6-10** — matches Bitwarden / 1Password's widest support; refuses 11+ (would emit biased leading
    digit).
  - **All 5 SHA variants** — SHA-1 default, plus 224 / 256 / 384 / 512 for programmatic flows.

  Runtime footprint: `node:crypto` only. Zero runtime dependencies.

  106 tests passing including RFC 4226 Appendix D (HOTP counters 0-9) and RFC 6238 Appendix B (TOTP × SHA-1 / SHA-256 /
  SHA-512 at five fixed timestamps). Pure JavaScript, TypeScript types from JSDoc.
