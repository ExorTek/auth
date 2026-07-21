# @exortek/shared

Private workspace utilities. Never published — this package is
consumed only within the monorepo, and every consumer bundles the
source files inline via their own build step. The published tarball
of each consumer therefore declares **zero** `@exortek/*` runtime
dependencies.

## Why

Every shipped package was carrying its own copy of the same
low-level primitives: base64url codec, per-key mutex, length-safe
`timingSafeEqual`, human-duration parser, algorithm registry, and so
on. Each copy could — and did — drift from the others.

This package is the single source of truth. Consumers import via
subpath (`@exortek/shared/base64url`), the bundler resolves the
workspace symlink and inlines the source, and the published tarball
ends up with the code but not the workspace dep.

## Layout

Flat — one module per file, subpath === filename.

```
src/
  algorithms.js      signing algorithm factories + createRegistry (RFC 7518/8037/8812)
  asserts.js         bindAsserts / defineGuards — per-package argument-guard binding
  base32.js          RFC 4648 §6 codec (case-insensitive decode)
  base64.js          RFC 4648 §4 codec (default unpadded, { pad: true } opt-in)
  base64url.js       RFC 4648 §5 codec (strict, canonical)
  bytes.js           string / Buffer / Uint8Array → Buffer coercion
  cookie.js          RFC 6265 parser + strict Set-Cookie serialiser
  crit.js            JWS `crit` header validation (RFC 7515 §4.1.11)
  crockford.js       Crockford Base32 codec + ALPHABET
  duration.js        human-duration parser → integer ms
  ecdsa.js           DER ↔ raw R‖S signature conversion
  errors.js          BaseError — shared error base class
  hmac.js            createHmac wrapper with encoding shortcut
  http.js            appendSetCookieHeader (framework-agnostic)
  key-resolver.js    verify-side polymorphic key resolver
  mutex.js           per-key async mutex
  normalize-key.js   JWK / Buffer / KeyObject → KeyObject factory
  random.js          CSPRNG randomBuffer(size) with validation
  redis-guard.js     duck-type check for Redis-compatible clients
  resolve.js         resolveOrCall / resolveHashFn / resolveEncoding
  sample.js          bias-free rejection sampling (alphabet + uint16)
  timing-safe.js     length-safe constant-time compare (no throw on length mismatch)
  validate.js        tiny schema builder — int / positiveInt / bytes / func / object / union / …
```

Import via flat subpaths: `@exortek/shared/base64url`,
`@exortek/shared/duration`, `@exortek/shared/mutex`, …

## Consumer pattern — thin wrappers

Shared utilities throw plain `Error` / `TypeError`. Each package keeps
a thin internal wrapper that translates failures into its own typed
error class at the surface boundary:

```js
// packages/jwt/src/internal/base64url.js
import * as sb from '@exortek/shared/base64url';
import { JwtError, ErrorCode } from './errors.js';

export function decode(text) {
  try {
    return sb.decode(text);
  } catch (err) {
    throw new JwtError(ErrorCode.INVALID_TOKEN, err.message);
  }
}
```

Error classes themselves come from the shared base class — one
subclass per package:

```js
// packages/session/src/errors.js
import { BaseError } from '@exortek/shared/errors';

export class SessionError extends BaseError {
  static statuses = { INVALID_ARGUMENT: 400 /* … */ };
  static defaultStatus = 500;
}
```

`err instanceof SessionError` keeps working in downstream code, and a
package that wants no HTTP `status` at all (e.g. `@exortek/crypto`)
simply declares no `statuses`.

## Argument-guard binding — `internal/guards.js`

Every package binds `@exortek/shared/asserts` to its own error class
once, in `src/internal/guards.js`, and every call site imports from
that local file:

```js
// packages/<pkg>/src/internal/guards.js  — 5 lines
import { defineGuards } from '@exortek/shared/asserts';
import { PasswordError, ErrorCode } from '../errors.js';

export const { assertString, assertPositiveInt, invalidArgument, parse } =
  defineGuards(PasswordError, ErrorCode.INVALID_ARGUMENT);
```

```js
// call site — throws the package's own typed error
import { assertPositiveInt, invalidArgument } from './internal/guards.js';
assertPositiveInt(options.iterations, 'options.iterations');
if (bytes.length < 16) throw invalidArgument('secret too short');
```

- `defineGuards(ErrorClass, code)` — one-line sugar; wraps
  `bindAsserts` with `(m, extra) => new ErrorClass(code, m, extra)`.
- `bindAsserts(wrap)` — raw factory for edge cases needing a custom
  wrap.
- `invalidArgument(msg, { cause })` — construct (don't throw) the
  bound error; use for `throw invalidArgument('…')` sites that don't
  fit `X must be Y`.
- `parse(schema, input, path?)` — bridge from `@exortek/shared/validate`
  schemas to the bound error class.

**Path-naming convention** for the `name` argument: `<publicFn>[.options|.config][.<field>]`
— e.g. `'createUser.name'`, `'scrypt.options.r'`, `'pepper.wrap.password'`.
