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
subpath (`@exortek/shared/encoding/base64url`), the bundler resolves
the workspace symlink and inlines the source, and the published
tarball ends up with the code but not the workspace dep.

## Layout

```
src/
  base32.js                  RFC 4648 §6 codec (case-insensitive decode)
  base64url.js               RFC 4648 §5 codec (strict, canonical)
  duration.js                human-duration parser → integer ms
  hash.js  hmac.js           node:crypto digest wrappers
  random.js                  CSPRNG buffer helper
  timing-safe.js             length-safe constant-time compare
  mutex.js                   per-key async mutex
  key-resolver.js            verify-side polymorphic key resolver
  resolve.js                 resolveOrCall / resolveHashFn / resolveEncoding
  errors.js                  BaseError — shared error base class
  validate.js                tiny schema builder for option validation
  algorithms.js              signing algorithm factories + createRegistry (RFC 7518/8037/8812)
  crit.js                    header crit validation (RFC 7515 §4.1.11)
  ecdsa.js                   DER ↔ raw R‖S signature conversion
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
