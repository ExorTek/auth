# @exortek/challenge

> Signed, single-use challenge tokens for multi-step auth flows on Node.js 22+ — HMAC-SHA256, opt-in single-use enforcement, opt-in IP binding, zero non-`@exortek/*` runtime dependencies. Built on `node:crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/challenge.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/challenge)
[![node](https://img.shields.io/node/v/@exortek/challenge.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/challenge)](https://packagephobia.com/result?p=@exortek/challenge)
[![license](https://img.shields.io/npm/l/@exortek/challenge.svg?color=blue)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)

A challenge is a small, HMAC-signed envelope that carries flow context — **who** is being challenged, **how** they proved themselves so far, **which step** of the flow they've cleared — from one HTTP request to the next without a server-side session record. It fills the awkward middle between an OTP code (single value, no context) and a JWT (heavier, meant for actual auth material).

Typical shape of a multi-step flow:

1. User posts password → server verifies → server issues a **challenge** with `method: 'password'`, `step: 'pw_verified'`, `nextStep: 'mfa'`.
2. Browser follows a redirect / opens an MFA prompt.
3. User submits a TOTP code + the challenge token.
4. Server verifies TOTP, then verifies the challenge (`expectedMethod: 'password'`, `expectedStep: 'pw_verified'`) — only *then* issues the real session.

The token is **stateless by default**. Single-use enforcement and IP binding are opt-in.

## Install

```bash
npm i @exortek/challenge
# or
yarn add @exortek/challenge
```

Node.js 22 LTS or newer.

## Quick start

```js
import { createChallenge, verifyChallenge } from '@exortek/challenge';

// One 32-byte secret, per environment. Rotate via env var, not code.
const SECRET = process.env.CHALLENGE_SECRET; // ≥ 32 UTF-8 bytes

// 1) After password succeeds
const token = await createChallenge({
  secret: SECRET,
  userId: 'usr_123',
  method: 'password',
  step: 'pw_verified',
  nextStep: 'mfa',
  expiresIn: '5m',
});
res.redirect(`/mfa?c=${token}`);

// 2) On the /mfa POST handler
const res = await verifyChallenge(req.body.c, {
  secret: SECRET,
  expectedMethod: 'password',
  expectedStep: 'pw_verified',
  expectedUserId: pendingUserIdFromCookie,
});
if (!res.valid) {
  return reply.code(401).send({ error: res.reason });
}
```

## Token format

```
<prefix>.<base64url(JSON payload)>.<base64url(HMAC-SHA256 tag)>
```

The default prefix is `chall_v1`. It's deliberately **not** a JWT: the versioned prefix lets a caller cheaply refuse a non-challenge token (or a future `chall_v2`) before ever running the HMAC. HMAC covers `<prefix>.<b64u payload>` — any change to prefix or payload invalidates the signature.

You can override the prefix at both `createChallenge` and `verifyChallenge` — e.g. `prefix: 'server_challenge'` or `prefix: 'myapp_v1'` — to brand the wire format for your service. The value must match `/^[A-Za-z0-9_-]{1,32}$/` (no `.` since it's the delimiter), and the same prefix must be used on both sides or verification returns `reason: 'malformed'`.

## API

### `createChallenge(options)`

```ts
createChallenge({
  secret:      string | Buffer | Uint8Array,   // ≥ 32 bytes
  expiresIn:   string | number,                 // '5m' / '15m' / 300000

  // Claims (all optional)
  userId?:     string,
  method?:     'totp' | 'hotp' | 'email_otp' | 'sms_otp' | 'backup_code'
             | 'passkey' | 'magic_link' | 'password' | 'webauthn'
             | 'oauth' | 'oidc' | string,
  step?:       string,
  nextStep?:   string,
  ua?:         string,
  metadata?:   Record<string, unknown>,

  // Security options
  singleUse?:  boolean,                         // requires `store`
  store?:      IncrStore,
  ipBinding?:  boolean,                         // requires `ip`
  ip?:         string,

  // Wire format
  prefix?:     string,                          // default 'chall_v1'; /^[A-Za-z0-9_-]{1,32}$/

  // Testing
  now?:        number,                          // override Date.now()
}): Promise<string>
```

Returns the compact token string. Throws `ChallengeError` with `ErrorCode.INVALID_ARGUMENT` on bad options or `ErrorCode.INVALID_SECRET` when the secret is under 32 bytes.

### `verifyChallenge(token, options)`

```ts
verifyChallenge(token, {
  secret:            string | Buffer | Uint8Array,
  consume?:          boolean,                    // requires `store`
  store?:            IncrStore,

  expectedUserId?:   string,
  expectedMethod?:   string,
  expectedStep?:     string,
  expectedNextStep?: string,
  ip?:               string,                     // required if token was IP-bound

  now?:              number,
}): Promise<
  | { valid: true, payload: ChallengePayload }
  | { valid: false, reason:
      'malformed' | 'bad_signature' | 'expired' | 'not_yet_valid'
      | 'user_mismatch' | 'method_mismatch' | 'step_mismatch'
      | 'next_step_mismatch' | 'ip_mismatch' | 'ip_missing'
      | 'replay' | 'store_unavailable'
    }
>
```

Never throws on user-input problems — a wrong or stale token is a normal auth outcome, not an error. Only throws `ChallengeError` on programmer bugs (bad options, wrong secret shape).

The 60-second clock-skew tolerance on `iat` covers ordinary NTP drift — verify only rejects tokens whose `iat` is clearly future-dated.

## Single-use enforcement

By default, a valid token can be replayed inside its expiry window. Pass `singleUse: true` at create time and `consume: true` at verify time — with the *same* store on both sides — and the second verify fails with `reason: 'replay'`:

```js
import { memoryStore } from '@exortek/challenge/stores';

const store = memoryStore(); // or redisStore(client) for multi-worker
const token = await createChallenge({
  secret: SECRET,
  expiresIn: '5m',
  singleUse: true,
  store,
});

const first = await verifyChallenge(token, {
  secret: SECRET, consume: true, store,
}); // { valid: true, payload: {...} }

const second = await verifyChallenge(token, {
  secret: SECRET, consume: true, store,
}); // { valid: false, reason: 'replay' }
```

The store is any object exposing `incr(key, ttlMs) → Promise<{ count }>`. `@exortek/security`'s rate-limit stores fit exactly — reuse yours if you already have one.

## IP binding

Bind the token to the origin IP so a stolen token from a different network refuses to verify:

```js
const token = await createChallenge({
  secret: SECRET,
  expiresIn: '5m',
  ipBinding: true,
  ip: req.ip,
});

const res = await verifyChallenge(token, {
  secret: SECRET,
  ip: req.ip,
}); // rejects with reason: 'ip_mismatch' from any other IP
```

Consider the trust boundary: mobile users on cellular networks change IPs frequently. Use for high-value flows (admin escalation, payment confirmation), not routine login.

## Stores

`@exortek/challenge/stores` ships two thin implementations:

- **`memoryStore(options?)`** — in-process Map with true LRU eviction (`maxKeys`, default 10,000; every `incr` refreshes the entry's position so a hot replay-guard tombstone can't be evicted before its TTL) and a background TTL sweep (`sweepMs`, default 60,000). Not cluster-safe: multi-worker deploys will double-consume. Fine for dev, single-node prod, sticky-session behind an LB, tests.
- **`redisStore(client, options?)`** — one Lua round-trip per verify (`INCR` + conditional `PEXPIRE`). Works with `ioredis`, `node-redis@4+`, `@upstash/redis`. `options.keyPrefix` defaults to `'chall:'`.

Both expose `incr(key, ttlMs)` and nothing else — the surface is intentionally tiny.

## Errors

```js
import { ChallengeError, ErrorCode } from '@exortek/challenge';

try {
  await createChallenge({ /* … */ });
} catch (err) {
  if (err instanceof ChallengeError) {
    if (err.code === ErrorCode.INVALID_SECRET) {
      // e.g. secret < 32 bytes
    }
    if (err.code === ErrorCode.INVALID_ARGUMENT) {
      // programmer bug — bad options shape
    }
  }
}
```

Branch on `err.code`, never on the message. Expected verify failures return a `reason` in the result object rather than throw.

## When to reach for something else

- **You need a full session with rotation, revocation, sudo mode.** Use `@exortek/session`.
- **You need an interoperable, third-party-verifiable token.** Use `@exortek/jwt`.
- **You just need a rate-limit key.** Use `@exortek/security`'s rate-limit — `challenge` is about carrying auth flow state, not counting requests.

## License

MIT
