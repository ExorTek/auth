# Contributing to `@exortek/auth`

Thanks for looking at the code. This document is the shortcut so you don't have to reverse-engineer conventions from the
git log. Keep it open in a tab while you work.

## Prerequisites

| Tool    | Version            | Why                                                                           |
| ------- | ------------------ | ----------------------------------------------------------------------------- |
| Node.js | **22.x or newer**  | Native test runner, stable `crypto.hkdfSync`, modern `Buffer` API.            |
| Yarn    | **4.x (Corepack)** | The repo pins `packageManager` in `package.json`. Run `corepack enable` once. |
| Git     | any recent         | Standard.                                                                     |

Windows works via WSL. Native Windows shells may hit path-separator quirks in test globs — the CI does not cover them.

## Getting set up

```bash
git clone https://github.com/ExorTek/auth.git
cd auth
corepack enable          # once per machine
yarn install
yarn build               # topological build of every publishable package
yarn test                # runs node:test across every workspace
```

If you're only touching one package, you can skip the root build:

```bash
cd packages/crypto
node --test 'tests/**/*.test.js'
```

## Branch naming

One prefix per branch, matching the intent of the change. Reviewers can filter their inbox by prefix.

| Prefix      | Use for                                    | Example                              |
| ----------- | ------------------------------------------ | ------------------------------------ |
| `feat/`     | New user-visible functionality.            | `feat/otp-backup-codes`              |
| `fix/`      | Bug fixes.                                 | `fix/base32-empty-input`             |
| `refactor/` | Internal cleanup, no behaviour change.     | `refactor/centralize-encoding-check` |
| `perf/`     | Performance work with no behaviour change. | `perf/base58-decode-loop`            |
| `docs/`     | README, CONTRIBUTING, JSDoc, ARCHITECTURE. | `docs/crypto-readme`                 |
| `test/`     | Test-only additions or reshuffles.         | `test/seal-clock-skew`               |
| `chore/`    | Repo housekeeping — CI, deps, config.      | `chore/upgrade-prettier`             |
| `release/`  | Cutting a version (Changesets).            | `release/v1.1.0`                     |

Keep branch names lower-kebab-case. Avoid trailing issue numbers; commits and PR descriptions carry those.

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org). One concern per commit. Present tense.

```
<type>(<scope>): <summary>

<body — what and why, wrapped at ~72 cols>
```

- **type** — `feat` · `fix` · `refactor` · `perf` · `docs` · `test` · `chore` · `build` · `ci`
- **scope** — the package or subsystem, most-specific first: `crypto/hash`, `crypto/cipher`, `crypto/internal`, `jwt`,
  `web`, or omit for repo-wide work.

Good examples pulled from the log:

```
feat(crypto/cipher): add seal / unseal for timed authenticated tokens
refactor(crypto/internal): centralize encoding validation & buffer coercion
chore: repo housekeeping — LICENSE, editorconfig, gitattributes
```

Avoid `wip`, `fixes stuff`, or squashing four unrelated changes into one commit. Split them.

## The change flow

1. **Open (or pick up) an issue.** New surface area — flag it first so we can check it fits the dependency graph in
   `ARCHITECTURE.md` before you build it.
2. **Branch off `master`.** Use the prefix above.
3. **Write code + tests + JSDoc.** Every public function needs JSDoc. Tests go next to the code
   (`packages/<pkg>/tests/**`).
4. **Add a changeset** (`yarn changeset`) — one per user-facing change. Refactor-only PRs don't need one.
5. **Run the local gate before pushing:**
   ```bash
   yarn format
   yarn lint
   yarn typecheck
   yarn test
   yarn build
   ```
6. **Push, open a PR.** Fill in the description with what changed and why. Draft PRs are welcome for early feedback.
7. **Address review.** Prefer new commits over force-pushes during discussion; squash on merge is decided at merge time.

## Testing

Every package uses **Node's native test runner** — no Jest, no Mocha, no Vitest. Tests colocate under
`packages/<name>/tests/**/*.test.js`.

```js
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fingerprint } from '../../src/index.js';

describe('fingerprint', () => {
  it('is stable across key order', () => {
    assert.equal(fingerprint({ a: 1, b: 2 }), fingerprint({ b: 2, a: 1 }));
  });
});
```

Coverage is available via `yarn test:coverage`. There is no coverage floor policy yet — cover the happy path plus one
negative case per branch.

## Style

- **ESLint (flat config)** — `prefer-const`, `no-var`, `eqeqeq: always`, `curly: all`, `no-unused-vars` (allow
  `_`-prefixed), `no-console: warn`.
- **Prettier** — semicolons on; single quotes; 120-col; ES5 trailing commas; arrows drop parens on single args
  (`arrowParens: 'avoid'`); LF line endings. The `.prettierrc` is the source of truth.
- **JSDoc** is required on every public function. `.d.ts` is emitted from JSDoc during `yarn build`.
- **Errors** — throw `CryptoError` (or the equivalent per-package error class) with a stable `code`. Never string-match
  error messages downstream.
- **No `console.*` in shipped code.** `no-console: warn` catches most of it.

## Working across packages

The dependency layering in [`ARCHITECTURE.md`](./ARCHITECTURE.md) is not optional. Do **not** import upward from a
lower-layer package. If you find yourself needing something in `@exortek/crypto` from `@exortek/jwt`, open an issue —
that's the sign the primitive belongs one layer down.

The umbrella `@exortek/auth` package re-exports everything and is the only place cross-package composition happens.

## Publishing

Releases are driven by [Changesets](https://github.com/changesets/changesets):

1. Author a changeset while your feature branch is open:
   ```bash
   yarn changeset
   ```
   Pick the packages you touched, pick a bump level (patch / minor / major), describe the change from the user's
   perspective.
2. Merge the PR. The changeset stays as a file under `.changeset/`.
3. A maintainer runs `yarn version` — this consumes the changesets, bumps `package.json` versions, and writes
   `CHANGELOG.md` per package.
4. `yarn release` publishes to npm and pushes tags.

Do not bump versions by hand. Do not publish from a feature branch.

## Reporting security issues

Please **do not** file a public GitHub issue for a security bug. Email [`memet@memet.dev`](mailto:memet@memet.dev) or
open a private security advisory on the repo. We'll acknowledge within a few days and coordinate disclosure.

## Questions

For anything that doesn't fit an issue template, start a [Discussion](https://github.com/ExorTek/auth/discussions).

Thanks for helping.
