# @exortek/otp

> Zero-dependency TOTP + HOTP for Node.js 22+ — built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/otp.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/otp)
[![tests](https://img.shields.io/badge/tests-106%20passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/otp.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/otp)](https://packagephobia.com/result?p=@exortek/otp)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![zero-deps](https://img.shields.io/badge/dependencies-0-brightgreen)](./package.json)
[![license](https://img.shields.io/npm/l/@exortek/otp.svg?color=blue)](./LICENSE)

RFC 4226 HOTP and RFC 6238 TOTP with secure defaults, tunable window / algorithm / digits, opt-in **replay defense** via
any store that implements `{ get, set }`, unambiguous **backup codes**, and Google-Authenticator-compatible
**provisioning URIs** for QR enrollment. No runtime dependencies — pure `node:crypto`.

📖 **Docs:** [**auth.memet.dev/otp**](https://auth.memet.dev/otp)

## Why

Every auth flow that adds 2FA rewrites the same ~200 lines of code, and most of them get one of these wrong:

- **Timing-safe compare.** `code === candidate` leaks the first matching character. `crypto.timingSafeEqual` fixes it —
  if you remember to use it.
- **Skew tolerance.** A user's phone drifts, the code changes while they're typing. If you don't accept the previous /
  next period, you reject valid users.
- **Replay defense.** A one-time code should be one-time. Without a server-side "seen" cache, an attacker who reads a
  valid code from a phishing page or a proxy log can use it inside the skew window.
- **Backup codes.** Random `Math.random()` codes with `O/0/1/I` glyphs that users can't tell apart on a printout. Or
  worse, storing them in plain text.
- **QR provisioning URI.** The `otpauth://` grammar is subtle — miss a URL-encode and half your users can't scan.

`@exortek/otp` ships every one of these correctly, and defaults to the values Google Authenticator + Authy + 1Password
all agree on.

## Install

```bash
npm  install @exortek/otp
yarn add     @exortek/otp
pnpm add     @exortek/otp
```

Requires **Node.js 22 or newer**. Zero runtime dependencies.

## Quick start

```js
import { generateSecret, provisioningUri, totp, verifyTotp, backupCodes } from '@exortek/otp';

// 1. Enrollment — mint a secret and turn it into a QR
const secret = generateSecret(); // base32, 20 bytes
const uri = provisioningUri({
  label: 'alice@example.com',
  issuer: 'MyApp',
  secret,
});
// Save `secret` to your users table. Render `uri` as a QR code
// (use any QR library — `qrcode` on npm is fine).

// 2. Backup codes — hand these to the user, hash before storing
const codes = backupCodes(10); // ['A3F4-9K2M', 'X7QP-5NB2', …]

// 3. Login — verify the 6-digit code
const ok = await verifyTotp(userInput, secret, { window: 1 });
if (!ok) return res.status(401).end('invalid code');
```

Ten lines and you have working 2FA. Add [replay defense](#replay-defense) for high-security flows.

## API

### `generateSecret(options?)`

```ts
generateSecret({
  bytes?:    number,               // default 20  (16..128)
  encoding?: 'base32'              // default — no padding
           | 'base32padded'
           | 'hex'
           | 'raw',
}): string
```

Cryptographically random. Default matches Google Authenticator's enrollment convention: 20 bytes, base32, no padding.

### `totp(secret, options?)`

```ts
totp(secret, {
  digits?:    6 | 7 | 8 | 9 | 10,           // default 6 — see compat table
  algorithm?: 'SHA1' | 'SHA224' | 'SHA256'  // default SHA1 — see compat table
           | 'SHA384' | 'SHA512',
  period?:    number,                       // seconds, default 30
  timestamp?: number,                       // ms since epoch — testing only
  t0?:        number,                       // RFC 6238 epoch offset (default 0)
}): string
```

Current TOTP for the given secret. Accepts base32 strings, hex, `Buffer`, or `Uint8Array`.

### `verifyTotp(code, secret, options?)`

```ts
verifyTotp(code, secret, {
  digits?:    6 | 7 | 8 | 9 | 10,
  algorithm?: 'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512',
  period?:    number,
  window?:    number,              // default 1  (±30s slop)
  timestamp?: number,
  t0?:        number,
  replay?: { store, key: string }, // opt-in — see below
}): Promise<boolean>
```

Returns `true` on match, `false` on any failure. **Never throws** on user-input problems — a wrong code is a normal auth
outcome, not an error.

### `remainingSeconds(period?, timestamp?)`

Seconds until the current TOTP code rolls over. Handy for the countdown ring most 2FA screens show.

### `hotp(secret, counter, options?)` / `verifyHotp(code, secret, counter, options?)`

Counter-based cousin. `verifyHotp` returns the **matched counter** (so you can advance your stored value) or `null` on
no match. Only looks _forward_ — used counters can never replay.

### `provisioningUri(options)`

```ts
provisioningUri({
  label:      string,              // usually the user's email
  secret:     string,              // base32
  issuer?:    string,              // your app name
  type?:      'totp' | 'hotp',     // default 'totp'
  digits?:    6 | 7 | 8 | 9 | 10,  // see compat table below
  period?:    number,              // TOTP only
  counter?:   number,              // HOTP — required
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512',
}): string
```

Emits the `otpauth://` URI Google Authenticator, Authy, 1Password, Bitwarden, Yubico Authenticator, and Aegis all
understand. Non-default parameters are omitted for maximum scanner compatibility.

### `backupCodes(n?, options?)`

```ts
backupCodes(n = 10, {
  length?:   number,               // default 10 chars per code
  groups?:   number,               // default 2 — 'ABCD-EFGH' style
  alphabet?: string,               // default Crockford (no O/0/1/I/L)
}): string[]
```

Unbiased CSPRNG draw from an unambiguous alphabet. **You** hash them before storage (bcrypt / argon2 / a strong HMAC
keyed with a server secret) — this package does not touch persistence.

### `normalizeBackupCode(input) / compareBackupCode(candidate, stored)`

Case-insensitive, whitespace / dash-tolerant, timing-safe verify for codes the user typed. Length mismatch does not
short-circuit.

### Errors

Every recoverable failure throws `OtpError` with a stable `code`. Branch on `code`, not on the message.

```js
import { OtpError, ErrorCode } from '@exortek/otp'

try {
  totp(malformedSecret)
} catch (err) {
  if (err instanceof OtpError && err.code === ErrorCode.INVALID_SECRET) { … }
}
```

Codes: `INVALID_ARGUMENT`, `INVALID_SECRET`, `INVALID_CODE`, `THROTTLED`, `REPLAY_DETECTED`, `UNSUPPORTED_ALGORITHM`.

## Authenticator app compatibility

If you're rendering a QR at enrollment, the values below reach every mainstream 2FA app. Deviate from them only when you
control the client.

**Universal safe defaults:**

- Algorithm: **SHA-1**
- Digits: **6**
- Period: **30 seconds**

**What each app accepts** (as of 2026):

| App                     | Algorithms              | Digits  | Period       |
| ----------------------- | ----------------------- | ------- | ------------ |
| Google Authenticator    | SHA-1 only              | 6 only  | 30 s only    |
| Microsoft Authenticator | SHA-1 only              | 6 only  | 30 s only    |
| Twilio Authy            | SHA-1, SHA-256          | 6, 7    | 10 or 30 s   |
| Aegis (Android)         | SHA-1, SHA-256, SHA-512 | 6, 7, 8 | 10 s – 60 s+ |
| 2FAS (iOS/Android)      | SHA-1, SHA-256, SHA-512 | 6, 7, 8 | flexible     |
| 1Password / Bitwarden   | SHA-1, SHA-256, SHA-512 | 6–10    | flexible     |
| FreeOTP (RedHat)        | SHA-1, SHA-256, SHA-512 | 6, 7, 8 | flexible     |
| Yubico Authenticator    | SHA-1, SHA-256, SHA-512 | 6, 8    | 30 or 60 s   |

**Notes:**

- `provisioningUri` will **refuse** to emit `SHA-224` / `SHA-384` — those work in the raw `hotp` / `totp` functions for
  server-server flows but are not in Google's Key URI Format spec and no Authenticator app parses them.
- `digits > 8` is accepted programmatically (up to 10) because Bitwarden and 1Password support it, but Google /
  Microsoft users won't be able to enroll.

## Replay defense

TOTP within its skew window is technically reusable — a code accepted at `T-1` still verifies at `T` and `T+1`.
Attackers who read a valid code from a phishing page have up to 90 seconds to use it.

The `replay` option makes verify **single-use per counter per key**:

```js
import { verifyTotp } from '@exortek/otp';
// Any store shaped like { get, set } — the @exortek/security stores fit:
import { rateLimit } from '@exortek/security';

const store = rateLimit.stores.memory();
// or rateLimit.stores.redis(client) for multi-worker deployments

async function verify(userId, code, secret) {
  return verifyTotp(code, secret, {
    window: 1,
    replay: { store, key: `user:${userId}` },
  });
}
```

Internally: on a successful verify, the matched counter is written to the store with a TTL that covers the remaining
acceptance window. Subsequent verifies inside that window with the same code will fail silently — the caller sees a
boolean `false`, no separate reason. Use `REPLAY_DETECTED` in your own logs if you want to distinguish.

**Redis for cluster deployments.** For high-security flows across multiple workers / regions, back the replay store with
Redis so a code accepted on one worker can't be replayed on another.

## Rate limiting

TOTP with a 6-digit code and `window: 1` gives an attacker a 3/1,000,000 chance per guess. Multiply by allowed retries
and you'll want a throttle in front:

```js
import { rateLimit } from '@exortek/security';

const throttle = rateLimit.sliding({
  requests: 5,
  window: '10m',
  store: rateLimit.stores.memory(),
});

async function verify(userId, code, secret) {
  const rl = await throttle.check({ key: `otp:${userId}` });
  if (!rl.allowed) throw new OtpError(ErrorCode.THROTTLED, `retry in ${rl.retryAfter}s`);
  return verifyTotp(code, secret, {
    window: 1,
    replay: { store: throttle.store, key: `user:${userId}` },
  });
}
```

## Highlights

- **Correct RFC test vectors.** Passes RFC 4226 Appendix D + RFC 6238 Appendix B for SHA-1, SHA-256, and SHA-512.
- **Timing-safe compare everywhere.** `verifyTotp` / `verifyHotp` / `compareBackupCode` all use `crypto.timingSafeEqual`
  on equal-length Buffers.
- **Secure defaults.** SHA-1 + 6 digits + 30s period + window: 1 — the only combination every mainstream Authenticator
  app understands. Everything else opt-in.
- **Unambiguous backup codes.** Crockford Base32 alphabet — no `0/O/1/I/L` on a printout.
- **Enrollment paste-friendly.** `decodeSecret` accepts spaces, mixed case, hex, and Buffer — matches how users copy
  from any 2FA app.

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek.
