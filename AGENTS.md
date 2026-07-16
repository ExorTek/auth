# AGENTS.md

Guidance for any AI coding agent — Claude Code, Cursor, Aider, GitHub Copilot Chat,
Windsurf, Zed AI — working in this repository. Written to be tool-agnostic; specific
per-tool notes live in each tool's own configuration (`.claude/`, `.cursorrules`, etc).

## Project

`@exortek/auth` — a framework-agnostic, server-only authentication toolkit for
Node.js 22+ positioned as a modern successor to Passport.js. Yarn-workspaces
monorepo of **22 packages** under the `@exortek/*` scope, each independently
versioned via Changesets and published to npm. Individual packages are also
consumable standalone; a planned umbrella `@exortek/auth` package will
re-export everything.

For which packages are currently shipped, check `README.md` (the source of
truth for shipping status). For the full designed surface, check
`ARCHITECTURE.md`.

## Repository layout

```
/
├── packages/<name>/      # every workspace package — see per-package layout below
├── web/                  # Nextra docs site (auth.memet.dev)
├── docs/                 # long-form Markdown (compliance mapping, etc.)
├── .changeset/           # pending version bumps
├── scripts/              # repo tooling (some entries gitignored)
├── ARCHITECTURE.md       # design doc — source of truth for planned APIs
├── AGENTS.md             # this file — agent-agnostic workflow guide
├── CONTRIBUTING.md       # human contributor guide
├── SECURITY.md           # vulnerability reporting + supported versions
└── README.md             # public entrypoint — the ground truth for shipping status
```

## Commands

Root:

```
yarn install
yarn build              # rollup, topological across workspaces
yarn build:watch        # parallel watch mode
yarn test               # node --test in each workspace
yarn test:coverage      # node --test --experimental-test-coverage
yarn typecheck          # tsc --noEmit per workspace
yarn lint               # eslint packages/*/src/**/*.js
yarn lint:fix
yarn format             # prettier --write .
yarn format:check       # CI uses this
yarn clean              # rm -rf dist tsconfig.tsbuildinfo per workspace
yarn changeset          # author a changeset (interactive)
yarn changeset:ver      # apply pending changesets — bumps versions + CHANGELOGs
yarn release            # login → changeset version → build → publish → tag
yarn verify             # typecheck + lint + format:check + test — the CI mirror
```

Per-package (from inside `packages/<name>/`):

```
yarn build                                # rollup -c + tsc emit
node --test 'tests/**/*.test.js'          # run all tests
node --test tests/path/to/file.test.js    # run one test file
```

CI (`.github/workflows/ci.yml`) runs `format:check → lint → typecheck → build →
test` on Node 22.x and 24.x. `publish.yml` runs the Changesets action on pushes
to `master`.

## Architecture

### Dependency layering (do not violate)

`@exortek/crypto` is the root of the tree; everything asymmetric can build up
from it. Key edges (from `ARCHITECTURE.md`):

```
crypto → jwk → jws → jwt → jwe → jwks
crypto → opaque, paseto, password, otp, magic-link, passkey,
         session, csrf, rate-limit, device, oauth2 → oidc,
         web3-evm, web3-solana
otp → challenge
apikey → rate-limit
auth (umbrella) → re-exports everything above
```

**Current policy: every package is fully standalone.** Cross-`@exortek/*`
dependencies are **not** taken today — utility duplication (e.g. `base64url` in
both `jwk` and `jws`) is accepted deliberately so a user who installs a single
package pulls no transitive workspace deps. The layering above tells you the
*semantic* order, not the runtime import graph.

`@exortek/crypto` may only depend on `node:crypto`. The single non-zero-dep
exception is `@exortek/web3-evm` (planned), which uses `ethereum-cryptography`.

### Server-only

**Every package in this monorepo is server-only.** They rely on `node:crypto`.
Do not introduce browser code, `crypto.subtle` polyfills, `window` / `document`
references, or `/client` subpaths — even for protocols with an inherent browser
side (WebAuthn, SIWE, SIWS, OAuth2 SPA/PKCE, OPAQUE).

We verify server-side and point users at a maintained client companion:

- **Passkey / WebAuthn** → `@simplewebauthn/browser`
- **SIWE (Ethereum)** → `viem` + optional `siwe`
- **SIWS (Solana)** → `@solana/wallet-adapter-react` + `@solana/web3.js`
- **OAuth2 SPA / PKCE (browser redirect)** → `oauth4webapi`
- **OPAQUE** → `@cloudflare/opaque-ts`

`@exortek/oauth2/client` (planned) is the OAuth term for the application
accessing the authorisation server — it is **server-side Node.js code**, not
browser code.

### Per-package conventions

Every package follows the same shape:

```
packages/<name>/
├── src/
│   ├── index.js              # public entrypoint; re-exports named surface + namespace
│   ├── <feature>/*.js        # implementation
│   └── internal/*.js         # helpers not part of the public API
├── tests/
│   └── *.test.js             # tests live here, NOT colocated in src/
├── rollup.config.js          # one-liner: re-exports createConfig(pkg)
├── tsconfig.json             # extends ../../tsconfig.base.json
├── package.json              # per-subpath exports, files, scripts
├── LICENSE                   # MIT — copy from a sibling package
├── README.md                 # public docs (badges, why, quick start, error catalogue)
└── CHANGELOG.md              # generated by Changesets on release
```

- `"type": "module"` everywhere. Dual output: `dist/<name>.mjs` (ESM) +
  `dist/<name>.cjs` (CJS). `.d.ts` emitted from JSDoc by `tsc --emitDeclarationOnly`.
- Tests live in `tests/` — the `test` script globs `tests/**/*.test.js`. Runs via
  Node's native test runner. **No Jest / Mocha / Vitest.**
- Packages that ship subpath exports use one rollup input/output pair per subpath.
  Current examples:
  - `@exortek/jwk` — `./generate`, `./import`, `./export`, `./thumbprint`, `./validate`
  - `@exortek/jws` — `./sign`, `./verify`, `./decode`, `./json`
  - `@exortek/oauth2` — `./providers/<name>` (planned)
  - `@exortek/passkey` — `./server` (planned; no `/client`)
- All builds externalise `node:*` plus declared deps / peerDeps via
  `rollup.config.base.js#createConfig`.

### TypeScript

Pure JavaScript with JSDoc types, not `.ts`. `tsc --emitDeclarationOnly`
generates `.d.ts` at build time. Maintain JSDoc on every public API — see
`ARCHITECTURE.md` §"JSDoc Yazım Kuralları" (~line 1968) and the worked
`@exortek/jwt` example (~line 2646) for the expected style before adding types
to a new module. `strict`, `noImplicitAny`, and `isolatedModules` are all on.

### Code style

ESLint (flat config) enforces: `prefer-const`, `no-var`, `eqeqeq: always`,
`curly: all`, `no-unused-vars` (allow `_`-prefixed), `no-console: warn`.
Prettier: no semicolons off — semicolons **on**, single quotes, ES5 trailing
commas, 100-char width, 2-space indent, always-parens arrows.

`yarn verify` runs all of these together — always let it pass before committing.

## Modern JOSE conventions (jwk / jws / jwt / jwe / jwks)

The JOSE stack in this repo makes some deliberate departures from `jose` (the
otherwise-excellent reference library). Preserve them when extending or
implementing new pieces:

- **Algorithm allowlist is mandatory on verify.** Omitting `options.alg` raises
  `MISSING_ALG_ALLOWLIST` — no default, no fallback.
- **`alg: 'none'` is refused everywhere.** No flag, no env var, no config. It
  raises `ALGORITHM_NONE_FORBIDDEN`. This is defence in depth: the algorithm
  table has no `none` entry *and* the sign / verify surfaces short-circuit
  before any lookup.
- **`crit` is strict by default.** Unknown critical headers raise
  `CRIT_UNSUPPORTED`. Callers can opt in named extensions via
  `knownCriticalHeaders`.
- **Key input is polymorphic** — JWK object, `KeyObject`, `Buffer` (HMAC only),
  JWK array (kid dispatch), and `async (header) => key` resolver functions are
  all first-class.
- **Granular `ErrorCode` enum per package.** Branch on `err.code`, never on
  `err.message`.
- **RFC test vectors are pinned in tests.** RFC 7638 §3.1 for JWK, RFC 7515
  Appendix A for JWS — spec-compliance canaries. When a curve or algorithm is
  added, add its published test vector.

## Workflow: building a new package end to end

Split the work into small, self-contained commits — each one should leave the
repository in a green state (`yarn verify` passes). A typical `@exortek/<name>`
build-out goes:

1. **Plan first.** Read the target section in `ARCHITECTURE.md`, weigh the
   differentiators vs. `jose` / `jsonwebtoken` / `helmet` / whichever incumbent
   the package is displacing, sketch the public surface, agree it with a
   maintainer before writing code. Save the plan to `.claude/plans/` (or the
   equivalent for other agents) so the shape survives context loss.
2. **Scaffold — one commit.** `package.json`, `rollup.config.js`,
   `tsconfig.json`, `LICENSE`, `README.md` stub, empty `src/**/*.js` stubs
   that throw `NOT_IMPLEMENTED`, one dummy `tests/smoke.test.js` if useful.
   `yarn install && yarn build` from the package directory must succeed —
   rollup should emit every subpath bundle even with stub implementations.
3. **Internal utility layer — one commit per concern (or one topical commit
   if concerns are tightly coupled).** `internal/errors.js` (the `ErrorCode`
   enum is a contract — freeze it early), `internal/base64url.js` if the
   package handles JOSE, algorithm registries, key normalisers, etc.
4. **Public surface — one commit per module.** `sign.js`, `verify.js`,
   `decode.js`, etc. — each with its own real implementation replacing the
   stub. Aim to keep each commit self-verifying: the tests you add here
   should exercise the code you just wrote.
5. **Tests — one commit per test file (or per test theme).** RFC test
   vectors first, then the algorithm / feature matrix, then the CVE / security
   surface, then edge cases. Every test file should be independently runnable.
6. **Docs pass 1 — one commit.** `packages/<name>/README.md` (badges, "why",
   quick start, error catalogue), `AGENTS.md` if the package changes a
   convention, `web/content/_meta.js`, `web/content/<name>/_meta.js`,
   `web/content/<name>/index.mdx`.
7. **Docs pass 2 — one commit.** `web/content/<name>/*.mdx` per-module deep
   dives.
8. **Changeset — one commit.** `.changeset/<name>-initial-release.md` with a
   `major` bump (workspace-local `0.0.0` → npm `1.0.0`).
9. **Verify.** `yarn verify` from the repo root. `cd packages/<name> && yarn
   npm publish --dry-run` to inspect the tarball. Optional: cross-check
   against the reference library (e.g. can `jose` verify a token we produce?).
10. **Release.** `git push --follow-tags` then `yarn release`. The release
    script now runs `changeset version` before publish; older scripts did
    not, which is how `@exortek/jwk@0.0.0` briefly escaped to npm.
11. **Post-release documentation sweep — one commit per file group.** Root
    `README.md` Shipping table + "N published" counter + install snippet,
    `web/content/index.mdx` Shipping table + stack row status, `SECURITY.md`
    supported versions row, `.github/ISSUE_TEMPLATE/*.yml` dropdown entry,
    `.github/pull_request_template.md` checkbox, `scripts/setup-labels.sh`
    label entry, `docs/compliance.md` if the package unlocks a
    NIST / ASVS / PCI row.

**Failure to walk step 11 is the most common release-time miss** — the
package hits npm but the repo still advertises "5 published" and issue
templates still miss it in their dropdown. Treat step 11 as part of the
release, not a follow-up.

## Workflow: fixing a bug

1. **Reproduce with a failing test first.** Bug reports without a failing
   test go back to the reporter — a fix without a regression test invites
   the same bug back.
2. **Root-cause it.** Do not paper over a symptom (e.g. widen a type,
   swallow an error) — trace to the actual defect. `[[design_philosophy]]`
   applies: every primitive ships a high-level helper; if a bug reveals a
   missing helper, the fix may be a new helper rather than a patched
   internal.
3. **Fix in the smallest possible diff.** One concern per commit. Don't
   refactor surrounding code in the fix commit — do it as a separate
   `refactor(<pkg>):` commit before or after.
4. **Add the regression test in the same commit** as the fix — the "why"
   line of the commit message names the CVE class, incident, or reporter
   where relevant.
5. **Changeset.** Patch-level bump unless the fix requires a behaviour
   change (fail-open → fail-closed counts as breaking for consumers who
   relied on the fail-open, so raise a minor or major bump and note it
   loudly in the changeset body).
6. **Release the fix.** Same `yarn release` flow. For high-severity fixes,
   deprecate previously-shipping vulnerable versions with `npm deprecate`
   pointing at the fixed release.

## Workflow: adding a feature to an existing package

1. **Confirm scope with a maintainer.** Additions to a published package's
   public surface are minor bumps at least; new subpaths, new algorithms,
   or new error codes touch the API contract.
2. **Add the ErrorCode first** if the feature introduces failure modes.
   The enum is a contract — extending it is trivial, but branching consumer
   code discovers the new code the moment it exists.
3. **Implementation → tests → docs → changeset.** Same rhythm as new
   packages, minus the scaffold.
4. **Cross-package effects.** If the feature would tempt you to import
   another `@exortek/*` package, first check whether it can be solved by
   accepting a plain object at the API boundary instead — the standalone
   policy is enforced.

## Workflow: refactor without behaviour change

1. **Prove there is no behaviour change** — the existing test suite must
   pass unchanged. If a test needs to change, it's not a pure refactor and
   should be split into a preceding behaviour commit.
2. **Refactor commits do not need a changeset** unless they touch a
   published file surface. Internal reshuffling is invisible to consumers.
3. **Batch related mechanical edits** (e.g. renaming a private helper
   across every file that imports it) into one commit — many small
   near-identical commits harm reviewability.

## Commit style

- **Small topical commits, split by concern.** A "scaffold" commit is separate
  from the "internal utility layer" commit is separate from the "tests" commit.
- Prefix with the conventional-commits type: `feat(<pkg>):`, `fix(<pkg>):`,
  `docs(<pkg>):`, `test(<pkg>):`, `chore(<pkg>):`, `refactor(<pkg>):`.
- Multi-line commit messages describe the *why* and note user-facing behaviour
  changes, especially around security-sensitive defaults.
- **No AI attribution.** Do not add "Co-Authored-By: <AI>" trailers or similar.

## Non-goals

Deliberate constraints — reject PRs that violate them:

- No browser code. Server-only, `node:crypto` only.
- No `alg: 'none'` anywhere, under any flag or environment variable.
- No sync APIs on primitives that Node 22+ ships async — everything is Promise-based.
- No cross-`@exortek/*` runtime dependencies (see standalone policy).
- No `SHA-1`-based JOSE algorithms.
- No unpinned `x5u` fetches (SSRF surface).
- No hand-rolled cryptographic primitives — everything delegates to `node:crypto`
  (which delegates to OpenSSL). The one long-term exception will be post-quantum
  when `node:crypto` exposes ML-DSA / ML-KEM natively (Node 25/26 timeframe).

## Notes

- `ARCHITECTURE.md` is the design doc for the whole 22-package surface — read
  the section for the package you are about to touch before writing code, and
  update it in the same PR when the surface you land differs from what was
  designed. Keep API names, config keys, and code identifiers exact.
- RFC references for each protocol package live in the "RFC & Standards
  References" section of `ARCHITECTURE.md`. Consult them when implementing
  JWT / JWS / JWE / JWK / JWKS / OAuth2 / OIDC / WebAuthn / PASETO behaviour
  rather than reverse-engineering vendor libraries.
- Anthropic Claude Code users: `.claude/` holds Claude-specific configuration
  and plan files (gitignored). Other agents pick up their configuration from
  their own conventions.
