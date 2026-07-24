# @exortek/password

> Argon2id, scrypt, bcrypt, and PBKDF2 under one coherent API — plus strength scoring, generation, policy, peppering,
> history, and HIBP breach lookup. Built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/password.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/password)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/password.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/password)](https://packagephobia.com/result?p=@exortek/password)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/password.svg?color=blue)](./LICENSE)

Every password-adjacent primitive a backend needs, in one package: four hash algorithms with automatic verify-time
routing, a strength meter, CSPRNG-based generator + diceware passphrases, a policy validator, peppering, password
history, and Have-I-Been-Pwned k-anonymity lookup. Zero required dependencies — argon2 and bcryptjs are **opt-in peers**
you install only if you need them.

📖 **Docs:** [**auth.memet.dev/password**](https://auth.memet.dev/password)

## Why

Every auth flow rewrites the same ~300 lines of password code, and most get one of these wrong:

- **Algorithm choice.** Bcrypt still fine? Scrypt or Argon2id better? PBKDF2 for FIPS? The right answer varies by threat
  model — the wrong answer is baked into every "hash your passwords" tutorial from 2016.
- **Migration.** You picked bcrypt in 2018 and want to move to Argon2id. Nobody ships a `verify()` that transparently
  routes across algorithms so you can rehash on the next login.
- **Unicode normalization.** `"café"` typed on iOS is one code point; typed on Android it's two. They hash differently.
  Users get locked out on new devices and nobody knows why.
- **72-byte bcrypt trap.** Bcrypt silently truncates input past 72 bytes. A 100-character passphrase hashes identically
  to its first 72 characters. Django and Passlib SHA-256 pre-hash to fix this; most Node tutorials don't mention it.
- **Strength scoring / policy.** Rolled by hand or pulled in a 400 KB `zxcvbn` dependency. Both are wrong for a signup
  form that already runs on a hot path.
- **Peppering.** Everyone talks about it, nobody ships it. A DB dump alone becomes useless if the pepper lives in KMS —
  but you have to wire the HMAC yourself.
- **HIBP breach lookup.** k-anonymity is 40 lines of code, but you'll cut corners on the User-Agent / timeout /
  fail-open dance.

`@exortek/password` ships every one of these correctly, with one API surface that's tree-shakeable and zero-dep by
default.

## Install

Base package — scrypt + pbkdf2 work out of the box on Node 22:

```bash
npm  install @exortek/password
yarn add     @exortek/password
pnpm add     @exortek/password
```

Add the algorithms you need — each is an **optional peer**, only install what you'll use:

| Want                                     | Extra install                                |
| ---------------------------------------- | -------------------------------------------- |
| **Argon2id** (OWASP 2024 recommendation) | `yarn add argon2`                            |
| **Bcrypt** (legacy migration, or newer)  | `yarn add bcryptjs` — pure JS, no build step |
| **Everything**                           | `yarn add argon2 bcryptjs`                   |

Requires **Node.js 22 or newer**. Base package has zero runtime dependencies.

## Quick start

```js
import { password } from '@exortek/password';

// 1. Signup — pick your algo, hash, store the PHC string
const stored = await password.scrypt.hash(input);
// $scrypt$ln=17,r=8,p=1$…$…

// 2. Login — auto-routes on stored hash format
const ok = await password.verify(input, user.pwHash);
if (!ok) return unauthorized();

// 3. Silent migration — if the stored hash's params are behind current defaults, rehash on the fly
if (password.needsRehash(user.pwHash)) {
  const fresh = await password.scrypt.hash(input);
  await db.users.update(user.id, { pw_hash: fresh });
}
```

Every algorithm lives under its own namespace — no `algorithm: 'scrypt'` flag on a mega-hash function:

```js
await password.argon2.hash(pw); // → $argon2id$v=19$m=19456,t=2,p=1$…
await password.scrypt.hash(pw); // → $scrypt$ln=17,r=8,p=1$…
await password.bcrypt.hash(pw); // → $2b$12$…       (requires bcryptjs peer)
await password.pbkdf2.hash(pw); // → $pbkdf2-sha256$i=600000$…
```

## API

### `password.verify(input, storedHash, options?)`

```ts
verify(input: string | Buffer | Uint8Array,
       storedHash: string,
       options?: { bcryptMode?: 'prehash' | 'strict' | 'truncate' }
      ): Promise<boolean>
```

Verify a candidate against a stored hash of **any** supported algorithm. The algorithm is auto-detected from the PHC
prefix (or bcrypt's `$2b$` shape). Returns `false` on any mismatch — including malformed or unrecognised stored values —
so login handlers never need a try/catch.

The only error raised is `MISSING_PEER_DEP`, surfaced when the stored hash needs `argon2` or `bcryptjs` and neither is
installed — actionable rather than silently returning `false` and looking like a wrong password.

### `password.needsRehash(storedHash, options?)`

```ts
needsRehash(storedHash: string, {
  target?: 'scrypt' | 'argon2id' | 'argon2i' | 'argon2d' | 'bcrypt' | 'pbkdf2-sha256' | 'pbkdf2-sha512',
  params?: object,
}): boolean
```

`true` when the stored hash's algorithm or parameters are weaker than the target. Default target is `scrypt` with this
package's OWASP-2024 defaults. Pair with `verify()` for the silent-migration pattern above.

### `password.identifyAlgorithm(storedHash)`

Returns the algorithm label (`'scrypt'`, `'argon2id'`, `'bcrypt'`, …) or `null` for unrecognised input. Useful for
migration telemetry.

### Algorithms

Every algo module exposes `hash`, `verify`, `needsRehash`, and a `*Defaults` constant. Options are per-algo:

```ts
password.scrypt.hash(pw, { N?: 131072, r?: 8, p?: 1, keyLength?: 32, saltLength?: 16 })
password.pbkdf2.hash(pw, { hash?: 'sha256' | 'sha512', iterations?: 600000, keyLength?: 32 })
password.argon2.hash(pw, { type?: 'argon2id' | 'argon2i' | 'argon2d',
                          memoryCost?: 19456, timeCost?: 2, parallelism?: 1 })
password.bcrypt.hash(pw, { rounds?: 12, mode?: 'prehash' | 'strict' | 'truncate' })
```

Defaults are OWASP 2024 first-line recommendations across the board. Every algo emits a self-describing
[PHC string](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) (bcrypt uses its native `$2b$`
format), so migrating between algorithms is a `verify → hash → store` triangle away.

### `password.strength(input, options?)`

```ts
strength(input, { userInfo?: string[] }): {
  score:                0 | 1 | 2 | 3 | 4,   // 0 trivial, 4 infeasible
  entropyBits:          number,
  weaknesses:           Array<'too-short' | 'single-class' | 'repetition' | 'sequential' | 'contains-user-info'>,
  lengthAfterNormalize: number,
}
```

Coarse offline strength meter — common-password bucketing, character-class entropy, repetition and sequential-run
detection, optional user-info substring check. Runs entirely offline; no dictionary bundled. For high-fidelity scoring
pair with `zxcvbn` in your form validator and use this as a backend sanity check.

### `password.generate(options?)` / `password.passphrase(options?)`

```ts
generate({ length?: 24, alphabet?: 'crockford' | 'alnum' | 'hex' | 'ascii' | 'urlSafe' | string }): string

passphrase({ words?: 6, separator?: '-', capitalize?: false, wordList?: string[] }): string
```

CSPRNG rejection-sampling generator (no modulo bias) and a diceware-style passphrase producer. Default alphabet is
Crockford Base32 minus `0/O/1/I/L` — terminal-safe and human-unambiguous.

### `password.policy(input, rules?)` / `password.assertPolicy(input, rules?)`

```ts
policy(input, {
  minLength?:       12,
  maxLength?:       1024,
  requireClasses?:  Array<'lower' | 'upper' | 'digit' | 'symbol'>,
  denyList?:        string[],           // e.g. company / product names
  userInfo?:        string[],           // e.g. email, username
  requireMinScore?: 0 | 1 | 2 | 3 | 4,
}): { valid: boolean, violations: string[], strength?: StrengthResult }
```

Structured validation with a machine-readable violation list. `assertPolicy` is the throw-on-invalid variant.

### `password.createPepper({ secret, hash?, encoding? })`

```ts
const pepper = createPepper({ secret: process.env.PW_PEPPER });
const stored = await password.scrypt.hash(pepper.wrap(input));
// later
const ok = await password.scrypt.verify(pepper.wrap(candidate), stored);
```

HMAC-based peppering. Keeps a DB dump alone useless against dictionary attack — the attacker needs the pepper too, which
lives in your KMS / secrets manager, **not** next to the hash table.

### `password.createHistory({ keepLast: 5 })`

```ts
const history = createHistory({ keepLast: 5 });
if (await history.isReused(newPw, user.previousHashes)) return badRequest('reused');
await db.users.update(user.id, {
  pw_hash: await password.scrypt.hash(newPw),
  previous_hashes: history.append(freshHash, user.previousHashes),
});
```

Stateless "don't reuse the last N passwords" helper. Walks the caller-supplied list via the umbrella `verify` router —
the history array can be mixed-algorithm during migration.

### `createHibpClient(options?)` (subpath `@exortek/password/hibp`)

```ts
import { createHibpClient } from '@exortek/password/hibp';

const hibp = createHibpClient({ userAgent: 'my-app/1.0' });
const check = await hibp.check(input, { failOpen: true });
if (check.pwned) return badRequest(`appears in ${check.count} known breaches`);
```

k-anonymity Have-I-Been-Pwned lookup — only the first 5 characters of SHA-1(password) ever leave the process. Uses
Node's global `fetch`; injectable for tests.

### Presets

```ts
import { presets } from '@exortek/password';

await password.argon2.hash(pw, presets.owasp2024.argon2); // default-equivalent, explicit
await password.scrypt.hash(pw, presets.sensitive.scrypt); // KMS-grade, ~1s per verify
await password.bcrypt.hash(pw, presets.interactive.bcrypt); // 50-80ms per verify
```

`owasp2024` (default-equivalent), `sensitive` (KMS-grade — ~1s), `interactive` (~50-80ms), and `fips` (PBKDF2-SHA-256,
NIST-approved).

### Errors

Every failure throws `PasswordError` with a stable `code`. Branch on `code`, not the message.

```js
import { PasswordError, ErrorCode } from '@exortek/password';

try {
  await password.bcrypt.hash(input);
} catch (err) {
  if (err instanceof PasswordError && err.code === ErrorCode.MISSING_PEER_DEP) {
    // bcryptjs not installed — the message tells the user exactly what to run
    logger.warn(err.message);
  }
}
```

Codes: `INVALID_ARGUMENT`, `UNSUPPORTED_ALGORITHM`, `MISSING_PEER_DEP`, `PASSWORD_TOO_LONG`,
`POLICY_VIOLATION`, `HIBP_UNAVAILABLE`.

## Algorithm choice

| Algorithm    | Node native? | Peer needed | When to pick                                       |
| ------------ | ------------ | ----------- | -------------------------------------------------- |
| **argon2id** | no           | `argon2`    | New deployments — OWASP 2024 gold standard         |
| **scrypt**   | ✓            | —           | New deployments — OWASP-approved, zero-dep default |
| **bcrypt**   | no           | `bcryptjs`  | Legacy migration or teams already on bcrypt        |
| **pbkdf2**   | ✓            | —           | FIPS 140-3 / NIST-only environments                |

Rule of thumb for new code: **argon2id** if you can afford the peer, **scrypt** if you want zero-dep. Bcrypt is fine but
slower to reach OWASP-grade cost, and PBKDF2 is CPU-only — GPU attackers win the arms race.

## Bcrypt 72-byte trap

Bcrypt silently truncates input longer than 72 bytes because of the original Blowfish key schedule. `@exortek/password`
handles this via a `mode` option, defaulting to the same fix Django, Passlib, and Laravel apply — SHA-256 pre-hash so
every byte contributes to the KDF:

```js
password.bcrypt.hash(pw, { mode: 'prehash' }); // default — safe, every byte contributes
password.bcrypt.hash(pw, { mode: 'strict' }); // refuse > 72 bytes with PASSWORD_TOO_LONG
password.bcrypt.hash(pw, { mode: 'truncate' }); // match legacy bcrypt behaviour — cross-library verify only
```

Pass the same `mode` to `bcrypt.verify` — bcrypt's format has no room to record it inline.

## Unicode normalization

All inputs are NFKC-normalized before hashing so `"café"` (composed) and `"café"` (decomposed) resolve to the same byte
sequence — same hash across iOS, Android, and macOS keyboards. Pass `{ normalize: false }` to opt out (very rarely
needed).

## Highlights

- **Four algorithms, one API.** `hash` / `verify` / `needsRehash` shape identical across scrypt, pbkdf2, argon2id, and
  bcrypt.
- **Auto-routing verify.** `password.verify(pw, stored)` inspects the PHC prefix and dispatches to the right algorithm —
  the migration hot path.
- **Silent rehash on login.** `needsRehash` reports parameter drift and cross-algorithm rehashes, so old users
  transparently upgrade to your current defaults.
- **NFKC by default.** Same password across composed / decomposed Unicode inputs.
- **Bcrypt 72-byte trap handled.** SHA-256 pre-hash by default — every byte contributes.
- **PHC-format everywhere.** Argon2, scrypt, and PBKDF2 emit self-describing strings; bcrypt uses its native format. No
  side database of params.
- **Timing-safe compare.** All native `crypto.timingSafeEqual`.
- **Zero required deps.** argon2 and bcryptjs are optional peers — pay only for what you use.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek.
