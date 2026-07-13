# @exortek/session

> Sealed-cookie session manager for Node.js — rotation, revocation, sudo mode, impersonation, concurrent limits,
> fingerprint binding, device labels, session events, Redis distributed revocation, CSRF derivation, trusted-device
> cookies, and adapters for Fastify, Express, Hono, and Elysia. Built on `@exortek/crypto`.

[![npm](https://img.shields.io/npm/v/@exortek/session.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/session)
[![tests](https://img.shields.io/badge/tests-144%20passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/@exortek/session.svg?color=339933)](https://nodejs.org)
[![types](https://img.shields.io/badge/types-included-3178C6)](./dist/index.d.ts)
[![license](https://img.shields.io/npm/l/@exortek/session.svg?color=blue)](./LICENSE)

Every session concern a backend needs, in one package: sealed encrypted cookies, rotation, revocation across
processes via Redis pub/sub, sudo mode for sensitive actions, impersonation with audit trail, concurrent session
limits, IP/UA fingerprint binding, auto-generated device labels for the settings page, CSRF token derivation, and a
long-lived "trusted device" cookie for skipping 2FA. Adapters for Fastify, Express, Hono, and Elysia.

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
| **Hono adapter**            | `yarn add hono`                                      |
| **Elysia adapter**          | `yarn add elysia`                                    |

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

  // opt-in features
  anonymous?:            boolean,                       // guest sessions
  concurrentLimit?:      number,                        // e.g. 3 → kicks oldest
  bindTo?:               Array<'ip' | 'ua'>,            // fingerprint binding
  impersonation?:        boolean,                       // enable impersonate() API
  deviceLabels?:         boolean,                       // auto-generated 'iPhone 14 · Chrome'
  events?: {                                            // audit trail
    onIssue, onVerify, onRotate, onRevoke, onDeny, onSuspicious,
  },
  suspiciousActivity?:   boolean | { onDetected },      // IP change flagging
  headerToken?: {                                       // Bearer header extraction
    headerName?: 'Authorization',
    prefix?:     'Bearer ',
  },
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
const sessions = createSessionManager({ ..., impersonation: true });

// Admin acts as user, session carries impersonatedBy: adminId
const { cookie } = await sessions.impersonate(adminReq, targetUserId, {
  reason: 'support ticket #4211',
});
```

### CSRF derivation

```js
import { deriveCsrfToken, verifyCsrfToken } from '@exortek/session';

const csrfSecret = process.env.CSRF_SECRET;
const csrf = deriveCsrfToken(session.id, csrfSecret);
// Render into a meta tag or non-HttpOnly cookie
// On mutating request:
if (!verifyCsrfToken(req.body._csrf, session.id, csrfSecret)) {
  return res.status(403).end();
}
```

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

### Hono

```js
import { sessionMiddleware } from '@exortek/session/hono';

const { middleware } = sessionMiddleware({ secret, ttl: '7d', idleTtl: '30m' });
app.use('*', middleware);

app.get('/me', c => {
  const session = c.get('session');
  return session ? c.json(session) : c.text('unauthorized', 401);
});
```

### Elysia

```js
import { sessionPlugin } from '@exortek/session/elysia';

const { plugin } = sessionPlugin({ secret, ttl: '7d', idleTtl: '30m' });

const app = new Elysia()
  .use(plugin)
  .get('/me', ({ session }) => session ?? { user: null });
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
- **Rolling touch** — idle TTL refreshes every request (with a 1-second write-amp guard)
- **Fingerprint binding** — IP / UA hash into the cookie payload; mismatch → hard revoke
- **Sudo mode** — `requireFreshAuth` + `markFresh` for sensitive actions
- **Impersonation** — admin-as-user with `impersonatedBy` audit trail
- **Concurrent limit** — 3 devices max, oldest kicked
- **CSRF derivation** — deterministic session-bound synchroniser token
- **Trusted-device cookie** — long-lived separate cookie for 2FA skip
- **Redis pub/sub** — cross-worker revocation propagation
- **Framework adapters** — Fastify, Express, Hono, Elysia
- **144 unit tests** — token roundtrip, rotation, revoke variants, fresh-auth, fingerprint binding,
  concurrent limit, impersonation, events, CSRF, trusted-device, adapter shape

## Links

- **Source:** [github.com/ExorTek/auth](https://github.com/ExorTek/auth)
- **Issues:** [github.com/ExorTek/auth/issues](https://github.com/ExorTek/auth/issues)
- **Changelog:** [CHANGELOG.md](./CHANGELOG.md)

## License

MIT © ExorTek.
