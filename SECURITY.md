# Security policy

## Supported versions

`@exortek/*` packages follow **semver**. Security fixes land on the current major line of each package; older major
lines are not patched unless the project has an explicit LTS commitment (none does today).

| Package             | Supported       |
| ------------------- | --------------- |
| `@exortek/crypto`   | `1.x` — current |
| `@exortek/security` | `1.x` — current |
| `@exortek/otp`      | `1.x` — current |
| `@exortek/password` | `1.x` — current |
| `@exortek/session`  | `1.x` — current |
| `@exortek/jwk`      | `1.x` — current |

Everything else in the roadmap is **not yet published** — file bug reports through the usual template once a version is
out.

## Reporting a vulnerability

**Do NOT open a public GitHub issue** for anything that could give an attacker a foothold.

### Preferred — GitHub Security Advisories

Use GitHub's private advisory flow:

**<https://github.com/ExorTek/auth/security/advisories/new>**

This routes the report privately to the maintainers, tracks fix progress, and eventually assigns a CVE if warranted.

### Fallback — email

If GitHub advisories don't work for you, send the report to:

**`memet@memet.dev`**

Please **use plain text** — encrypted mail is welcome but not required. Include:

- Affected package(s) + version(s)
- Node.js version + operating system
- A description of the issue and the impact you're worried about
- A proof-of-concept or minimal reproduction, if you have one

If you'd like credit in the eventual advisory, tell us the name / handle to use. If you'd rather stay anonymous, we'll
keep you off the credits.

## What to expect

- **Acknowledgement:** within **72 hours** of receipt (usually much faster).
- **Triage:** we'll confirm whether we can reproduce, agree on severity, and share a rough timeline within **7 days**.
- **Fix window:** we aim to publish a patched release within **30 days** of triage for confirmed high/critical issues,
  longer for low-severity ones.
- **Coordinated disclosure:** we publish the advisory once a fixed version is on npm. If you have a public disclosure
  date in mind (talk, blog post, etc.) tell us early — we'll do our best to align.

## Scope

**In scope**

- Any published `@exortek/*` package listed under "Supported versions".
- The build/publish pipeline (npm tarball contents, dist/ integrity).

**Out of scope**

- **Third-party dependencies** — report those to their maintainers. Where a fix would land in one of our packages (e.g.
  we're using a known-vulnerable version), we do want to hear about it.
- **Denial-of-service via legitimate rate limits.** If our rate limiter slows you down when you're calling it "too
  much", that's the documented behaviour.
- **Docs site typos, missing pages, broken CSS.** Those go through the regular issue tracker.
- **Feature-request-disguised-as-vulnerability** ("your library should do X"). Please use the feature request template.

## Hardening guarantees

Every package in this repository is written to hold these invariants. Deviations are treated as bugs and fall under the
reporting policy above.

- **No hand-rolled crypto.** Every primitive delegates to `node:crypto` (OpenSSL-backed) or a well-audited peer
  (`argon2`, `bcryptjs`). We don't reimplement HMAC, AES-GCM, PBKDF2, scrypt, or Blake2 in JavaScript.
- **Timing-safe comparison** for every user-supplied secret compare — passwords, OTP codes, backup codes, CSRF tokens,
  seal tag checks. Uses `crypto.timingSafeEqual` on equal-length Buffers.
- **Constant-time verify paths** where user-existence would otherwise leak via response latency
  (`password.constantTimeVerify`, `otp.verifyTotp` with the CAS replay guard).
- **No `Math.random()`** anywhere in a security-relevant path. Every randomness source is `crypto.randomBytes` with
  rejection sampling where a bounded alphabet is involved.
- **Prototype-pollution defence** on any user-supplied JSON in `@exortek/security` — `__proto__` / `constructor` /
  `prototype` keys are dropped unconditionally, survivors written as own properties via `Object.defineProperty`.
- **Default XFF distrust** on edge-runtime adapters (Hono / Elysia rate-limit) — `X-Forwarded-For` is client-controlled
  without a proxy in front, so we require an explicit `trustProxy: true` opt-in.
- **Every failure carries a machine-readable code** (`CryptoError`, `SecurityError`, `OtpError`, `PasswordError`,
  `SessionError`, `JwkError`, `JwsError`) so callers branch on `code`, not on message text that can change across versions.
- **RFC test-vector coverage** for every standardised primitive: RFC 4226 Appendix D (HOTP), RFC 6238 Appendix B (TOTP),
  RFC 7914 §12 (scrypt), RFC 8018 (PBKDF2), RFC 9106 (Argon2), RFC 7638 §3.1 (JWK thumbprint), and RFC 7515 Appendix A
  (JWS reference tokens for HS256 / RS256 / ES256 / ES512). `yarn test` from the workspace root exercises them.
- **Peer isolation for optional native bindings** — `argon2` / `bcryptjs` load lazily and are cached at runtime, so a
  scrypt-only or pbkdf2-only consumer pays nothing and the umbrella can import cleanly even when the peer is missing.

## Third-party audit

An external code review of the crypto- and auth-critical paths is planned. When completed, the report will be linked
from this document and summarised in the affected packages' CHANGELOGs. Until then the packages are self-reviewed
against the invariants above and the RFC test vectors linked from each package's README.

## Safe-harbour

If you're testing in **good faith** against your own installation of our packages, we consider your research authorised:

- Only test against installations you control.
- Do not access or modify data that isn't yours.
- Do not degrade service for other users.
- Do not disclose publicly until we've had a reasonable window (see fix window above) — or 90 days from initial triage,
  whichever comes first.

We won't pursue legal action against researchers who play by these rules. We can't extend safe-harbour to third parties
whose systems happen to run our code, so please don't test against them.
