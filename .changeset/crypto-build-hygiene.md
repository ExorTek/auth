---
'@exortek/crypto': patch
---

Build hygiene: `build` and `clean` scripts now remove `dist/` **and** `tsconfig.tsbuildinfo` before every build. Without the pre-clean, `tsc --incremental` could skip regenerating type declarations for removed/renamed source files, leaving stale `.d.ts` artifacts inside `dist/` — which `files: ["dist"]` would then ship in the tarball.
