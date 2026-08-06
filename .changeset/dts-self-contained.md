---
'@exortek/apikey': patch
'@exortek/challenge': patch
'@exortek/crypto': patch
'@exortek/jwe': patch
'@exortek/jwk': patch
'@exortek/jwks': patch
'@exortek/jws': patch
'@exortek/jwt': patch
'@exortek/magic-link': patch
'@exortek/oauth2': patch
'@exortek/opaque': patch
'@exortek/otp': patch
'@exortek/paseto': patch
'@exortek/passkey': patch
'@exortek/password': patch
'@exortek/security': patch
'@exortek/session': patch
'@exortek/ua': patch
---

Ship self-contained TypeScript declarations. Every package's emitted `.d.ts`
referenced `@exortek/shared` (e.g. `import { BaseError } from '@exortek/shared/errors'`),
but `@exortek/shared` is a private, never-published workspace package that is
inlined into each bundle at build time. A TypeScript consumer therefore hit
`Cannot find module '@exortek/shared/…'` (with `skipLibCheck` off) or silently
degraded error-class types like `ApiKeyError` — losing its constructor
signature and `.code` / `.message` — with `skipLibCheck` on.

The build now runs a declaration-bundling pass (`rollup-plugin-dts`) after
`tsc`, flattening each entry's `.d.ts` and inlining the `@exortek/shared` types
so the shipped declarations are fully self-contained. Runtime deps and `node:*`
stay external. No runtime or API change — types only.
