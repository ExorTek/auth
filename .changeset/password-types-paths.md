---
'@exortek/password': patch
---

- **Fix TypeScript type resolution for the algorithm subpaths.** `@exortek/password/{scrypt,pbkdf2,argon2,bcrypt}` pointed their `types` field at `./dist/<name>.d.ts`, but `tsc` mirrors the source tree and actually emits at `./dist/algorithms/<name>.d.ts`. TS consumers of these subpaths got `Could not find a declaration file` — runtime worked, types didn't. `exports` now points at the correct nested paths.
- Remove a dead `if (rounds < 10)` branch in `bcrypt.assertRounds` — the intended soft-warn was never implemented, only a comment sat there.
- Build hygiene: `build` / `clean` now also remove `tsconfig.tsbuildinfo` so `tsc --incremental` cannot leave stale `.d.ts` artifacts behind.
