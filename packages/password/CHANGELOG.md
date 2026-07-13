# @exortek/password

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
