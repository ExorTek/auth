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
  encoding/                  RFC 4648 §5 codec
  time/                      human-duration parser
  crypto/                    length-safe compare, hash, hmac wrappers
  concurrency/               per-key async mutex
  errors/                    base error class + status map
  polymorphic.js             resolveOrCall / resolveEncoding
  signing/                   sign/verify flow shared utilities
```

## Consumer pattern — error factory

Shared utilities that need to throw typed errors accept a factory so
each consumer's own error class (e.g. `JwtError`) is preserved:

```js
// packages/shared/src/encoding/base64url.js
export function createBase64url(ErrorClass, ErrorCode) {
  return {
    encode(bytes) { … },
    decode(text) {
      if (!ALPHABET.test(text)) throw new ErrorClass(ErrorCode.INVALID_TOKEN, …);
      …
    },
  };
}

// packages/jwt/src/internal/base64url.js
import { createBase64url } from '@exortek/shared/encoding/base64url';
import { JwtError, ErrorCode } from './errors.js';
export const { encode, decode, encodeJson } = createBase64url(JwtError, ErrorCode);
```

`err instanceof JwtError` keeps working in downstream code — the
factory guarantees the thrown class matches the consuming package.
