# @exortek/magic-link

> Passwordless email-link auth for Node.js 22+ — HMAC-signed short-lived tokens, single-use enforcement, opt-in per-email rate limiting, email hashed into the payload, memory + Redis stores. Ships the token — you send the email.

[![npm](https://img.shields.io/npm/v/@exortek/magic-link.svg?color=cb3837)](https://www.npmjs.com/package/@exortek/magic-link)
[![node](https://img.shields.io/node/v/@exortek/magic-link.svg?color=339933)](https://nodejs.org)
[![install size](https://packagephobia.com/badge?p=@exortek/magic-link)](https://packagephobia.com/result?p=@exortek/magic-link)
[![license](https://img.shields.io/npm/l/@exortek/magic-link.svg?color=blue)](./LICENSE)
[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/ExorTek/auth/actions/workflows/ci.yml)

A passwordless sign-in flow is three moving parts:

1. **Mint** an HMAC-signed short-lived token bound to an email + a store record.
2. **Email** the token as a URL — that's your mail driver's job (Sendgrid, Resend, SES, SMTP — the choice stays yours).
3. **Verify** the token in your `/auth/verify` route: match the signature, check expiry, atomically consume so the same link cannot be replayed, hand back the email + metadata.

`@exortek/magic-link` ships steps 1 and 3. Step 2 stays entirely in your control.

## Install

```bash
npm i @exortek/magic-link
# or
yarn add @exortek/magic-link
```

Node.js 22 LTS or newer.

## Token format

```
<prefix>.<base64url(JSON payload)>.<base64url(HMAC-SHA256 tag)>
```

Default prefix `mlink_v1`. Payload is intentionally minimal:

- `id`  — 128-bit random, the store lookup key.
- `iat` / `exp` — seconds since epoch.
- `eh`  — `SHA-256(secret ‖ email)` when `hashEmail: true` (default).

The email never appears in the URL — only in the store. `redirectTo` (if any) also stays in the store, so it cannot be tampered with by editing the link. If your `/request-magic-link` endpoint accepts `redirectTo` from user input, validate it before passing it to `createMagicLink` — treat it like any redirect target (e.g. with `@exortek/security`'s `safeRedirect`).

## Quick start

```js
import { createMagicLink, verifyMagicLink } from '@exortek/magic-link';
import { memoryStore } from '@exortek/magic-link/stores';

const SECRET = process.env.MAGIC_LINK_SECRET; // ≥ 32 UTF-8 bytes
const store = memoryStore();

// 1) User submits their email — mint a link
const { token, url, id } = await createMagicLink({
  secret: SECRET,
  email: 'user@example.com',
  baseUrl: 'https://myapp.com/auth/verify',
  expiresIn: '15m',
  redirectTo: '/dashboard',
  store,
});

// 2) YOUR job — send the email
await mailer.send({
  to: 'user@example.com',
  subject: 'Sign in to MyApp',
  text: `Click to sign in (expires in 15 minutes): ${url}`,
});

// 3) On the /auth/verify route
const res = await verifyMagicLink(req.query.token, {
  secret: SECRET,
  store,
});
if (!res.valid) return reply.code(401).send({ error: res.reason });

// res = { valid: true, id, email, redirectTo?, metadata? }
// Issue your session cookie / JWT / whatever, then redirect:
reply.redirect(res.redirectTo ?? '/');
```

## API

### `createMagicLink(options)`

```ts
createMagicLink({
  secret:      string | Buffer | Uint8Array,   // ≥ 32 bytes
  email:       string,
  baseUrl:     string,                          // where /auth/verify lives
  expiresIn:   string | number,                 // '15m' / '1h' / ms

  redirectTo?: string,                          // stored in the record, not the URL
  metadata?:   Record<string, unknown>,

  hashEmail?:  boolean,                         // default true
  prefix?:     string,                          // default 'mlink_v1'

  store:       MagicLinkStore,
  maxPerEmail?: { count: number, window: string | number },

  now?:        number,                          // override Date.now() for tests
}): Promise<{ token, url, id, expiresAt, record }>
```

`url` is `baseUrl` + `?token=<token>` (or `&token=` when `baseUrl` already has a query string). Everything except the token is stored server-side.

### `verifyMagicLink(token, options)`

```ts
verifyMagicLink(token, {
  secret:         string | Buffer | Uint8Array,
  store:          MagicLinkStore,
  consume?:       boolean,                      // default true
  expectedEmail?: string,
  prefix?:        string,                       // must match create-time prefix
  now?:           number,
}): Promise<
  | { valid: true, id, email, redirectTo?, metadata? }
  | { valid: false, reason }
>
```

Never throws on a bad token — a wrong / stale / used link is a normal auth outcome. Failure reasons:

| Reason                    | Meaning                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `malformed`               | Wrong shape, wrong length, wrong prefix.                       |
| `bad_signature`           | HMAC didn't match — wrong secret or the payload was tampered.  |
| `expired`                 | `exp` passed.                                                  |
| `not_yet_valid`           | `iat` is more than 60 s in the future (clock skew).            |
| `not_found`               | Well-shaped but the id is not in the store.                    |
| `consumed`                | Store already saw a successful consume for this id.            |
| `email_mismatch`          | `expectedEmail` differs from the payload's `eh` or the record. |
| `email_binding_mismatch`  | Payload's `eh` disagrees with the stored record's email — a poisoned row was swapped under a valid id. |
| `store_unavailable`       | `store.getById` / `store.consume` threw.                       |

### Two-phase preview → confirm flow

Sometimes you want the click on the email to open a preview page, and only the second click ("Yes, sign me in") to consume. Pass `consume: false` on the first verify, then a follow-up POST with `consume: true`:

```js
// GET /auth/verify?token=... — preview
const preview = await verifyMagicLink(token, {
  secret: SECRET, store, consume: false,
});
// Render "Sign in as preview.email?" with a POST form.

// POST /auth/verify — confirm
const done = await verifyMagicLink(token, { secret: SECRET, store });
```

### Rate limiting per email

Prevent a spammer from burning your mail budget:

```js
await createMagicLink({
  secret: SECRET,
  email,
  baseUrl,
  expiresIn: '15m',
  store,
  maxPerEmail: { count: 3, window: '1h' },
});
// → throws MagicLinkError { code: 'RATE_LIMITED' } after the 3rd call
//   within an hour for that email
```

The counter lives on the same store (`store.incrRate` — memory + Redis both ship it). This is a coarse limit on the `create` side — for `/auth/verify` DoS protection, put `@exortek/security`'s rate-limit in front of the route (the token itself is 128-bit random + HMAC-gated, so brute-forcing isn't the concern).

### Pepper-free by design

There's no `peppers` array here (unlike `@exortek/apikey`). Magic-link tokens are single-use and short-lived — a stolen storage row is worth much less than a leaked API-key hash, and the extra rotation surface isn't worth the ergonomic cost. If you need HSM-style key rotation, keep the `secret` in a KMS and rotate it as a whole.

## Sending the email

The package produces `url`. How it reaches the user is up to you.

### Resend

```js
import { Resend } from 'resend';
const resend = new Resend(process.env.RESEND_API_KEY);

await resend.emails.send({
  from: 'MyApp <auth@myapp.com>',
  to: email,
  subject: 'Sign in to MyApp',
  html: `<p>Click to sign in (expires in 15 minutes):</p>
         <p><a href="${url}">Sign in</a></p>`,
});
```

### Sendgrid

```js
import sgMail from '@sendgrid/mail';
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

await sgMail.send({
  to: email,
  from: 'auth@myapp.com',
  subject: 'Sign in to MyApp',
  html: `<a href="${url}">Sign in</a>`,
});
```

### Nodemailer (SMTP)

```js
import nodemailer from 'nodemailer';
const transporter = nodemailer.createTransport({ /* your SMTP */ });

await transporter.sendMail({
  from: 'auth@myapp.com',
  to: email,
  subject: 'Sign in to MyApp',
  html: `<a href="${url}">Sign in</a>`,
});
```

Whatever driver you pick, make the link clickable — plain-text URLs sometimes get mangled by mail clients that insert soft line breaks.

## Stores

`@exortek/magic-link/stores` ships two implementations. Any object matching the `MagicLinkStore` interface works — bring your own if you already have an appropriate table in your DB.

- **`memoryStore()`** — in-process Map with `structuredClone` semantics (deep-copy on read + write so caller mutation cannot escape). Reverse index by email + a per-email rate counter. Not cluster-safe.
- **`redisStore(client, { keyPrefix? })`** — JSON blob per id + SADD-set per email + Lua CAS `consume` + Lua INCR-with-PEXPIRE `incrRate`. `keyPrefix` defaults to `'mlink:'`. Works with `ioredis`, `node-redis@4+`, `@upstash/redis`.

### The interface

```ts
interface MagicLinkStore {
  put(record: MagicLinkRecord): Promise<void>;
  getById(id: string): Promise<MagicLinkRecord | null>;
  consume(id: string): Promise<boolean>; // atomic CAS
  incrRate?(email: string, ttlMs: number): Promise<{ count: number }>;
  listByEmail?(email: string): Promise<MagicLinkRecord[]>;
  revokeByEmail?(email: string): Promise<number>;
}
```

`incrRate` is required only when the caller sets `maxPerEmail`. `listByEmail` / `revokeByEmail` are required only for `listPendingForEmail` / `revokeAllForEmail`.

## Errors

```js
import { MagicLinkError, ErrorCode } from '@exortek/magic-link';
```

| Code                | HTTP | Raised when |
| ------------------- | ---- | ----------- |
| `INVALID_ARGUMENT`  | 400  | Options object is missing, misshapen, or violates an invariant. |
| `INVALID_SECRET`    | 400  | Secret is under 32 bytes / wrong type. |
| `INVALID_PREFIX`    | 400  | Prefix doesn't match `/^[A-Za-z0-9_-]{1,32}$/`. |
| `RATE_LIMITED`      | 429  | `maxPerEmail` cap exceeded. |
| `STORE_ERROR`       | 500  | `store.put` threw at create time (rare — usually a DB outage). |

## License

MIT
