import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import {
  MagicLinkError,
  ErrorCode,
  createMagicLink,
  hashEmailValue,
  listPendingForEmail,
  revokeAllForEmail,
  verifyMagicLink,
} from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';

const SECRET = randomBytes(32);
const BASE_URL = 'https://myapp.com/auth/verify';

test('round-trip: create → verify returns { valid: true, email }', async () => {
  const store = memoryStore();
  try {
    const { token, url } = await createMagicLink({
      secret: SECRET,
      email: 'user@example.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    assert.match(token, /^mlink_v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    assert.match(url, new RegExp(`^${BASE_URL.replace('/', '\\/')}\\?token=`));
    const res = await verifyMagicLink(token, { secret: SECRET, store });
    assert.equal(res.valid, true);
    if (res.valid) assert.equal(res.email, 'user@example.com');
  } finally {
    store._stop();
  }
});

test('consume defaults to true — second verify with same token → consumed', async () => {
  const store = memoryStore();
  try {
    const { token } = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    const first = await verifyMagicLink(token, { secret: SECRET, store });
    assert.equal(first.valid, true);
    const second = await verifyMagicLink(token, { secret: SECRET, store });
    assert.equal(second.valid, false);
    assert.equal(second.reason, 'consumed');
  } finally {
    store._stop();
  }
});

test('consume: false — link stays valid for a second verify (two-phase flow)', async () => {
  const store = memoryStore();
  try {
    const { token } = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    const a = await verifyMagicLink(token, { secret: SECRET, store, consume: false });
    const b = await verifyMagicLink(token, { secret: SECRET, store, consume: false });
    assert.equal(a.valid, true);
    assert.equal(b.valid, true);
  } finally {
    store._stop();
  }
});

test('verify: malformed on bogus / non-string inputs', async () => {
  const store = memoryStore();
  try {
    for (const input of ['', 'nope', 'mlink_v0.a.b', 'mlink_v1.only-two', null]) {
      const res = await verifyMagicLink(input, { secret: SECRET, store });
      assert.equal(res.valid, false);
      assert.equal(res.reason, 'malformed');
    }
  } finally {
    store._stop();
  }
});

test('verify: wrong secret → bad_signature', async () => {
  const store = memoryStore();
  try {
    const { token } = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    const res = await verifyMagicLink(token, { secret: randomBytes(32), store });
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'bad_signature');
  } finally {
    store._stop();
  }
});

test('verify: expired', async () => {
  const store = memoryStore();
  try {
    const { token } = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '5m',
      store,
      now: 1_000_000,
    });
    const res = await verifyMagicLink(token, {
      secret: SECRET,
      store,
      now: 1_000_000 + 6 * 60_000,
    });
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'expired');
  } finally {
    store._stop();
  }
});

test('expectedEmail: match passes, wrong email fails (short-circuit via eh)', async () => {
  const store = memoryStore();
  try {
    const { token } = await createMagicLink({
      secret: SECRET,
      email: 'right@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    const ok = await verifyMagicLink(token, {
      secret: SECRET,
      store,
      expectedEmail: 'right@x.com',
    });
    assert.equal(ok.valid, true);
    // Wrong expected → email_mismatch even without touching the store,
    // because the payload carries eh (default hashEmail: true).
    const store2 = memoryStore();
    try {
      // Fresh store — proves the reject comes from eh, not from store lookup.
      const bad = await verifyMagicLink(token, {
        secret: SECRET,
        store: store2,
        expectedEmail: 'wrong@x.com',
      });
      assert.equal(bad.valid, false);
      assert.equal(bad.reason, 'email_mismatch');
    } finally {
      store2._stop();
    }
  } finally {
    store._stop();
  }
});

test('hashEmail: false — expectedEmail check still works via the store record', async () => {
  const store = memoryStore();
  try {
    const { token } = await createMagicLink({
      secret: SECRET,
      email: 'right@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      hashEmail: false,
      store,
    });
    const bad = await verifyMagicLink(token, {
      secret: SECRET,
      store,
      expectedEmail: 'wrong@x.com',
    });
    assert.equal(bad.valid, false);
    assert.equal(bad.reason, 'email_mismatch');
  } finally {
    store._stop();
  }
});

test('email binding: poisoned store row swap detected via eh cross-check', async () => {
  const store = memoryStore();
  try {
    const { token, id } = await createMagicLink({
      secret: SECRET,
      email: 'real@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    // Simulate a poisoned store: swap the email under the same id.
    const rec = await store.getById(id);
    rec.email = 'attacker@x.com';
    await store.put(rec);
    const res = await verifyMagicLink(token, { secret: SECRET, store });
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'email_binding_mismatch');
  } finally {
    store._stop();
  }
});

test('redirectTo + metadata are returned on successful verify', async () => {
  const store = memoryStore();
  try {
    const { token } = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      redirectTo: '/dashboard',
      metadata: { intent: 'login', ip: '1.2.3.4' },
      store,
    });
    const res = await verifyMagicLink(token, { secret: SECRET, store });
    assert.equal(res.valid, true);
    if (res.valid) {
      assert.equal(res.redirectTo, '/dashboard');
      assert.deepEqual(res.metadata, { intent: 'login', ip: '1.2.3.4' });
    }
  } finally {
    store._stop();
  }
});

test('maxPerEmail: exceeding cap throws RATE_LIMITED', async () => {
  const store = memoryStore();
  try {
    const opts = {
      secret: SECRET,
      email: 'spammer@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
      maxPerEmail: { count: 3, window: '1h' },
    };
    await createMagicLink(opts);
    await createMagicLink(opts);
    await createMagicLink(opts);
    await assert.rejects(
      createMagicLink(opts),
      err => err instanceof MagicLinkError && err.code === ErrorCode.RATE_LIMITED,
    );
  } finally {
    store._stop();
  }
});

test('maxPerEmail: distinct emails have independent counters', async () => {
  const store = memoryStore();
  try {
    const base = {
      secret: SECRET,
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
      maxPerEmail: { count: 2, window: '1h' },
    };
    await createMagicLink({ ...base, email: 'a@x.com' });
    await createMagicLink({ ...base, email: 'a@x.com' });
    // 'b' is fresh — should not be capped.
    await createMagicLink({ ...base, email: 'b@x.com' });
  } finally {
    store._stop();
  }
});

test('secret shorter than 32 bytes → INVALID_SECRET', async () => {
  const store = memoryStore();
  try {
    await assert.rejects(
      createMagicLink({
        secret: 'too-short',
        email: 'u@x.com',
        baseUrl: BASE_URL,
        expiresIn: '15m',
        store,
      }),
      err => err instanceof MagicLinkError && err.code === ErrorCode.INVALID_SECRET,
    );
  } finally {
    store._stop();
  }
});

test('bad email shape → INVALID_ARGUMENT', async () => {
  const store = memoryStore();
  try {
    for (const bad of ['not-an-email', '@x', 'x@', '', null]) {
      await assert.rejects(
        createMagicLink({
          secret: SECRET,
          email: bad,
          baseUrl: BASE_URL,
          expiresIn: '15m',
          store,
        }),
        err => err instanceof MagicLinkError && err.code === ErrorCode.INVALID_ARGUMENT,
      );
    }
  } finally {
    store._stop();
  }
});

test('custom prefix round-trips; mismatch → malformed', async () => {
  const store = memoryStore();
  try {
    const { token } = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
      prefix: 'login_v1',
    });
    assert.ok(token.startsWith('login_v1.'));
    const ok = await verifyMagicLink(token, { secret: SECRET, store, prefix: 'login_v1' });
    assert.equal(ok.valid, true);
    const bad = await verifyMagicLink(token, { secret: SECRET, store }); // default prefix
    assert.equal(bad.valid, false);
    assert.equal(bad.reason, 'malformed');
  } finally {
    store._stop();
  }
});

test('url: appends ?token= when baseUrl has no query string', async () => {
  const store = memoryStore();
  try {
    const { url } = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: 'https://x.com/verify',
      expiresIn: '15m',
      store,
    });
    assert.match(url, /^https:\/\/x\.com\/verify\?token=/);
  } finally {
    store._stop();
  }
});

test('url: appends &token= when baseUrl already has a query string', async () => {
  const store = memoryStore();
  try {
    const { url } = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: 'https://x.com/verify?lang=en',
      expiresIn: '15m',
      store,
    });
    assert.match(url, /\?lang=en&token=/);
  } finally {
    store._stop();
  }
});

test('listPendingForEmail: returns non-consumed, non-expired records only', async () => {
  const store = memoryStore();
  try {
    const a = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    // Consume one.
    await verifyMagicLink(a.token, { secret: SECRET, store });
    const pending = await listPendingForEmail('u@x.com', { store });
    assert.equal(pending.length, 1);
  } finally {
    store._stop();
  }
});

test('revokeAllForEmail: invalidates every pending link for the email', async () => {
  const store = memoryStore();
  try {
    const a = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    const b = await createMagicLink({
      secret: SECRET,
      email: 'u@x.com',
      baseUrl: BASE_URL,
      expiresIn: '15m',
      store,
    });
    const n = await revokeAllForEmail('u@x.com', { store });
    assert.equal(n, 2);
    assert.equal((await verifyMagicLink(a.token, { secret: SECRET, store })).valid, false);
    assert.equal((await verifyMagicLink(b.token, { secret: SECRET, store })).valid, false);
  } finally {
    store._stop();
  }
});

test('hashEmailValue: deterministic + secret-namespaced', () => {
  const a = hashEmailValue(SECRET, 'x@y.com');
  const b = hashEmailValue(SECRET, 'x@y.com');
  const c = hashEmailValue(randomBytes(32), 'x@y.com');
  assert.equal(a, b);
  assert.notEqual(a, c);
});
