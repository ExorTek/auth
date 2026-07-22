# @exortek/session

> Sealed-cookie session manager for Node.js — rotation, revocation, sudo mode, impersonation, concurrent limits,
> fingerprint binding, device labels, session events, Redis distributed revocation, CSRF derivation, trusted-device
> cookies, and adapters for Fastify and Express. Built on `@exortek/crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/session.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/session)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/session.svg?color=339933)](https://nodejs.org)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/session.svg?color=blue)](./LICENSE)

Every session concern a backend needs, in one package: sealed encrypted cookies, rotation, revocation across
processes via Redis pub/sub, sudo mode for sensitive actions, impersonation with audit trail, concurrent session
limits, IP/UA fingerprint binding, auto-generated device labels for the settings page, CSRF token derivation, and a
long-lived "trusted device" cookie for skipping 2FA. Adapters for Fastify and Express.

📖 **Docs:** [**auth.memet.dev/session**](https://auth.memet.dev/session)

## Why

Every session library ships the same first 20% correctly (sign a cookie, verify it, expire it) and then hands the
remaining 80% off to the user:

- **Rotation.** When user privilege changes, when a token is on its 6th hour, when secrets are being cycled — you need
  to swap the cookie without kicking the user out. Nobody ships this.
- **Revocation across workers.** You revoke session X on worker A. Worker B still has it cached. Every session
  library says "use Redis" and stops there — nobody wires the pub/sub propagation.
- **Sudo mode.** GitHub, AWS, Google — every serious app has step-up authentication for sensitive actions. No Node
  session lib ships it.
- **Concurrent limit.** "You're signed in on 4 devices, sign out one" — universal UX pattern, nobody ships the state
  machine.
- **Impersonation.** Admin panels want to log in as a user to reproduce a bug. Every serious platform has this. No one
  ships an audit-trailed helper.
- **Fingerprint binding.** IP + UA hash bound to the cookie — invalidate on mismatch. Everyone rolls it themselves.
- **CSRF derivation.** Session-bound synchroniser tokens — the "double submit" variant that ties the CSRF value to the
  session it belongs to.
- **Device labels.** "iPhone 14 · Safari" instead of a 300-character UA blob on the settings/sessions page. Trivial,
  never included.

`@exortek/session` ships every one of these — enabled by config flags, disabled by default, so you pay only for what
you use.

## Install

```bash
npm  install @exortek/session
yarn add     @exortek/session
pnpm add     @exortek/session
```

Optional peers — install only what you use:

| Want                        | Extra install                                        |
| --------------------------- | ---------------------------------------------------- |
| **Redis store + pub/sub**   | `yarn add ioredis` **or** `yarn add redis`           |
| **Fastify adapter**         | `yarn add fastify`                                   |
| **Express adapter**         | `yarn add express`                                   |

Requires **Node.js 22 or newer**. Base package requires `@exortek/crypto`.

## Quick start

```js
import { createSessionManager } from '@exortek/session';

const sessions = createSessionManager({
  secret: process.env.SESSION_SECRET,
  ttl:     '7d',
  idleTtl: '30m',
});

// Signup / login
const { cookie, session } = await sessions.issue({
  userId: user.id,
  claims: { roles: ['admin'] },
});
res.setHeader('Set-Cookie', cookie);

// Middleware
const current = await sessions.verify(req);
if (!current) return unauthorized();

// Logout
const { cookie: bye } = await sessions.revoke(req);
res.setHeader('Set-Cookie', bye);
```

## API

### `createSessionManager(config)`

```ts
createSessionManager({
  secret:  string | Buffer | Array<string | Buffer>,   // [newest, …older] for rotation
  ttl:     string | number,                             // absolute lifetime, e.g. '7d'
  idleTtl: string | number,                             // rolling window, e.g. '30m'

  cookie?: {
    name?:      '__Host-sid',
    domain?:    string,
    path?:      '/',
    sameSite?:  'lax' | 'strict' | 'none',
    secure?:    boolean,
    httpOnly?:  boolean,
  },

  store?:      SessionStore,                            // default sessionStore.memory()
  touchEvery?: string | number,                         // rolling-touch write frequency
                                                        //   default: min('60s', idleTtl / 2)

  // opt-in features
  anonymous?:            boolean,                       // guest sessions
  concurrentLimit?:      number,                        // e.g. 3 → kicks oldest
  bindTo?:               Array<'ip' | 'ua'>,            // fingerprint binding
  bindStrictness?:       'strict' | 'soft',             // strict (default): hard revoke on
                                                        // mismatch. soft: fire onSuspicious
                                                        // and let the request through (good
                                                        // for mobile users on 5G ↔ wifi)
  impersonation?:        boolean,                       // enable impersonate() API
  impersonationTtl?:     string | number,               // default '30m'
  deviceLabels?:         boolean,                       // auto-generated 'iPhone 14 · Chrome'
  events?: {                                            // audit trail
    onIssue, onVerify, onRotate, onRevoke, onDeny, onSuspicious,
  },
  suspiciousActivity?:   boolean | { onDetected },      // IP + UA change flagging
})
```

### Lifecycle

- `issue({ userId, claims?, deviceLabel?, rememberMe?, req?, now? })` — mint a new session, return `{ token, cookie, session }`
- `verify(req, { now? })` — decrypt + validate + touch. Returns `Session` or `null`
- `rotate(req, { claims?, now? })` — new token, old revoked. For privilege escalation
- `touch(sessionId, { now? })` — refresh idle TTL manually
- `revoke(req, { reason?, now? })` — logout — invalidate + delete-cookie
- `revokeById(sessionId, { reason? })` — admin path
- `revokeAllForUser(userId, { reason? })` — compromise scenario
- `revokeAllExceptCurrent(req, { reason? })` — password-change UX
- `listActive(userId)` — active sessions for a settings page
- `upgrade(req, userId, { mergeClaims?, now? })` — attach a userId to an anonymous session,
  revoke the guest record, mint an authenticated session with merged claims (guest-checkout flow)

### Sudo mode (step-up auth)

Sensitive-endpoint gating — user must be recently re-authenticated:

```js
// On a hassas endpoint:
if (!(await sessions.requireFreshAuth(req, { maxAgeSeconds: 300 }))) {
  return res.redirect('/reauth');
}
// After successful re-auth:
await sessions.markFresh(req);
```

### Impersonation (opt-in with audit trail)

```js
const sessions = createSessionManager({
  ...,
  impersonation:    true,
  impersonationTtl: '15m',    // default '30m' — impersonation sessions run on a short TTL
});

// Admin acts as user, session carries impersonatedBy + impersonationReason
const { cookie, session } = await sessions.impersonate(adminReq, targetUserId, {
  reason: 'support ticket #4211',
  ttl:    '5m',              // per-call override wins over impersonationTtl
});
// session.impersonatedBy === adminId
// session.impersonationReason === 'support ticket #4211'
```

An admin session that is itself impersonated cannot start a second layer — impersonation
never nests, so audit trails stay flat.

### CSRF derivation

```js
import { deriveCsrfToken, verifyCsrfToken, maskCsrfToken, unmaskCsrfToken } from '@exortek/session';

const csrfSecret = process.env.CSRF_SECRET;
const raw = deriveCsrfToken(session.id, csrfSecret);   // deterministic, session-bound

// Ship a fresh mask per render so response compression can't reveal the token
// through a BREACH-class oracle.
const masked = maskCsrfToken(raw);
res.render('form', { csrf: masked });

// On the mutating request the client echoes the masked value back; unmask
// before verifying.
const submitted = unmaskCsrfToken(req.body._csrf);
if (!verifyCsrfToken(submitted, session.id, csrfSecret)) {
  return res.status(403).end();
}
```

`maskCsrfToken` XORs the raw token against a fresh random pad and returns
`pad || (token ⊕ pad)`. Every render sends a different string; the pad travels
alongside it so the server can recover the original. Skipping the mask is fine
when responses are not compressed or the token never lands in the HTML body
(SPA that reads it from a header, for example).

### Trusted device cookie (subpath)

Long-lived separate cookie for "remember this device for 30 days" 2FA skip:

```js
import { createTrustedDeviceCookie } from '@exortek/session/trusted-device';

const trusted = createTrustedDeviceCookie({
  secret: process.env.TD_SECRET,
  ttl:    '30d',
});

// After successful 2FA + tickbox
res.setHeader('Set-Cookie', trusted.issue(userId));

// Before TOTP prompt
if (trusted.verify(req, userId)) {
  return signInWithoutOtp();
}
```

### Session events (audit trail)

```js
const sessions = createSessionManager({
  ...,
  events: {
    onIssue:     session => logger.info({ session }, 'session issued'),
    onVerify:    session => metrics.increment('session.verify'),
    onRotate:    (oldId, s) => audit.log('rotate', { oldId, new: s.id }),
    onRevoke:    (sid, reason) => audit.log('revoke', { sid, reason }),
    onDeny:      (reason, req) => logger.warn({ reason }, 'session denied'),
    onSuspicious: e => alerts.notify(e.userId, 'ip-change', e),
  },
});
```

## Store adapters

### Memory (default)

```js
import { sessionStore } from '@exortek/session';
const store = sessionStore.memory({ maxSessions: 100_000, sweepMs: 60_000 });
```

Single-process only. Full LRU eviction, background sweep for expired entries.

### Redis (subpath)

```js
import { redisStore } from '@exortek/session/stores/redis';
import Redis from 'ioredis';

const client = new Redis(process.env.REDIS_URL);
const store = redisStore(client, {
  keyPrefix:          'sess:',
  publishRevocations: true,    // cross-worker cache invalidation
  channel:            'sess:events',
});

const sessions = createSessionManager({ ..., store });
```

Works with `ioredis` **or** `node-redis@4+`. `publishRevocations: true` emits every revoke to
`<keyPrefix>events` via `PUBLISH` — subscribe with a second connection to invalidate per-request caches on other
workers.

## Framework adapters

Each adapter installs `req.session` (or `c.get('session')`) + a `sessions` handle to the manager for calling
`rotate`, `impersonate`, etc.

### Fastify

```js
import { sessionPlugin } from '@exortek/session/fastify';

const { plugin } = sessionPlugin({
  secret: process.env.SESSION_SECRET,
  ttl:     '7d',
  idleTtl: '30m',
});

await app.register(plugin);

app.get('/me', async (req, reply) => {
  if (!req.session) return reply.code(401).send({ error: 'unauthenticated' });
  return req.session;
});
```

### Express

```js
import { sessionMiddleware } from '@exortek/session/express';

const { middleware } = sessionMiddleware({ secret, ttl: '7d', idleTtl: '30m' });
app.use(middleware);

app.get('/me', (req, res) => {
  if (!req.session) return res.sendStatus(401);
  res.json(req.session);
});
```

## Errors

Every recoverable failure throws `SessionError` with a stable `code`. Branch on `code`, not on the message.

```js
import { SessionError, ErrorCode } from '@exortek/session';

try {
  await sessions.rotate(req);
} catch (err) {
  if (err instanceof SessionError && err.code === ErrorCode.INVALID_TOKEN) {
    return res.redirect('/login');
  }
  throw err;
}
```

Codes: `INVALID_ARGUMENT`, `MISSING_TOKEN`, `INVALID_TOKEN`, `EXPIRED`, `IDLE_TIMEOUT`, `REVOKED`, `SESSION_NOT_FOUND`,
`TOKEN_ROTATION_REQUIRED`, `FINGERPRINT_MISMATCH`, `SUSPICIOUS_ACTIVITY`, `CONCURRENT_LIMIT_EXCEEDED`,
`FRESH_AUTH_REQUIRED`, `IMPERSONATION_INVALID`, `MISSING_PEER_DEP`.

## Compliance

- **OWASP ASVS V3** — Session token generation, cookie flags, `__Host-` prefix binding, server-side invalidation on
  logout, absolute + idle TTLs, cross-session rotation on privilege change.
- **NIST SP 800-63B §5.2.10** — Reauthentication cadence via `requireFreshAuth`.
- **PCI-DSS 4.0 §8.3** — Concurrent session limit via `concurrentLimit`.

## Highlights

- **Sealed cookie by default** — encrypted opaque claims, stateless verify hot-path
- **Per-request cache** — 3 verify calls in one request → 1 decryption
- **Multi-secret rotation** — cycle the encryption key without invalidating in-flight tokens
- **Rolling touch with `touchEvery`** — idle TTL refreshes cost one store write per interval
  (default 60s / half of idleTtl, whichever is smaller)
- **Fingerprint binding** — IP / UA hash in the cookie payload;
  `bindStrictness: 'strict'` (default) hard-revokes on mismatch, `'soft'` lets the request
  through and fires `onSuspicious` (mobile 5G ↔ wifi friendly)
- **Sudo mode** — `requireFreshAuth` + `markFresh` for sensitive actions
- **Impersonation** — admin-as-user with `impersonatedBy` + `impersonationReason` audit trail
  and a short 30 min default TTL; nesting refused
- **Concurrent limit** — 3 devices max, oldest kicked, limit-drop convergence via
  `while (active >= limit)` eviction
- **Anonymous → auth upgrade** — guest-cart claims survive the login via `sessions.upgrade`
- **CSRF derivation** — deterministic session-bound synchroniser token +
  per-render `maskCsrfToken` for BREACH resistance
- **Trusted-device cookie** — long-lived separate cookie for 2FA skip; reserved payload
  fields protected from `extraClaims` clobber
- **Redis + tombstones** — revocation lives in its own key, immune to concurrent
  rolling-touch writes overwriting it (the old lost-revoke class of bug)
- **Redis pub/sub** — cross-worker revocation propagation
- **Framework adapters** — Fastify, Express (both with cookie append)
- **163 unit tests** — token roundtrip, rotation (incl. concurrent-rotate race),
  concurrent-limit convergence, revoke variants, fresh-auth, fingerprint binding
  (both strictness modes), impersonation (TTL, nest-refusal), events, CSRF (masking too),
  trusted-device (claim-clobber regression), all four adapter shapes, and a live Redis
  integration suite that covers the tombstone lost-revoke scenario end-to-end
  (opt-in via `REDIS_URL`)

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek.
