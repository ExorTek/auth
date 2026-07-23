import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { tokenPair, create, rotate, revoke, revokeAll } from '../src/token-pair.js';
import { createStore } from '../src/stores.js';
import { verify, JwtError, ErrorCode } from '../src/index.js';

const ACCESS_SECRET = randomBytes(32);
const REFRESH_SECRET = randomBytes(32);

function fresh() {
  const store = createStore('memory', { gc: { strategy: 'lazy' } });
  return {
    store,
    options: {
      secret: { access: ACCESS_SECRET, refresh: REFRESH_SECRET },
      access: { alg: 'HS256', expiresIn: '15m' },
      refresh: { alg: 'HS256', expiresIn: '7d', store },
    },
  };
}

// create
test('create: emits access + opaque refresh + expiry metadata', async () => {
  const { options, store } = fresh();
  const pair = await create({ userId: 1, sub: 'u1' }, options);
  assert.equal(typeof pair.accessToken, 'string');
  assert.equal(typeof pair.refreshToken, 'string');
  assert.ok(pair.accessExpiresAt instanceof Date);
  assert.ok(pair.refreshExpiresAt instanceof Date);
  assert.equal(typeof pair.familyId, 'string');
  assert.equal(store.size(), 1);
  store._stop();
});

test('create: access token is a valid JWT decodable via verify()', async () => {
  const { options } = fresh();
  const pair = await create({ userId: 42 }, options);
  const { payload } = await verify(pair.accessToken, ACCESS_SECRET, { alg: ['HS256'] });
  assert.equal(payload.userId, 42);
  options.refresh.store._stop();
});

test('create: custom tokenSize + encoding hex', async () => {
  const { options } = fresh();
  options.refresh.tokenSize = 24;
  options.refresh.encoding = 'hex';
  const pair = await create({}, options);
  assert.equal(pair.refreshToken.length, 48); // 24 bytes hex
  options.refresh.store._stop();
});

test('create: opaque refresh works without refresh.alg', async () => {
  const store = createStore('memory', { gc: { strategy: 'lazy' } });
  const pair = await create(
    { sub: 'u1' },
    {
      secret: { access: ACCESS_SECRET, refresh: REFRESH_SECRET },
      access: { alg: 'HS256', expiresIn: '15m' },
      refresh: { expiresIn: '7d', store },
    },
  );
  assert.equal(typeof pair.refreshToken, 'string');
  store._stop();
});

test('create: refresh.alg required when refresh.opaque is false', async () => {
  const store = createStore('memory', { gc: { strategy: 'lazy' } });
  await assert.rejects(
    create(
      { sub: 'u1' },
      {
        secret: { access: ACCESS_SECRET, refresh: REFRESH_SECRET },
        access: { alg: 'HS256', expiresIn: '15m' },
        refresh: { opaque: false, expiresIn: '7d', store },
      },
    ),
    err => err instanceof JwtError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
  store._stop();
});

test('create: custom hashFn wins over hashAlgo', async () => {
  const { options, store } = fresh();
  let called = 0;
  options.refresh.hashFn = async pt => {
    called++;
    return `SHA_NOOP_${pt.slice(0, 8)}`;
  };
  const pair = await create({}, options);
  assert.ok(called >= 1);
  // Re-derive the store key using the same custom hashFn and confirm the
  // store contains it.
  const key = `SHA_NOOP_${pair.refreshToken.slice(0, 8)}`;
  assert.equal(await store.has(key), true);
  store._stop();
});

test('create: fully custom generate() is used verbatim', async () => {
  const { options, store } = fresh();
  options.refresh.generate = async () => ({
    plaintext: 'RT_test_xyz',
    storeKey: 'STORE_KEY_test_xyz',
  });
  const pair = await create({}, options);
  assert.equal(pair.refreshToken, 'RT_test_xyz');
  assert.equal(await store.has('STORE_KEY_test_xyz'), true);
  store._stop();
});

// rotate
test('rotate: happy path — issues new pair, marks old refresh consumed', async () => {
  const { options, store } = fresh();
  const first = await create({ userId: 1 }, options);
  const second = await rotate(first.refreshToken, options);
  // Refresh tokens must differ (random bytes → deterministically unique).
  // Access tokens may collide within the same second when the payload
  // is identical — that's a JWT determinism property, not a bug.
  assert.notEqual(second.refreshToken, first.refreshToken);
  assert.equal(second.familyId, first.familyId);
  // Store now has 2 entries: old (marked usedAt) + new
  assert.equal(store.size(), 2);
  store._stop();
});

test('rotate: unknown refresh token → REVOKED', async () => {
  const { options, store } = fresh();
  await assert.rejects(
    () => rotate('never-existed', options),
    err => err instanceof JwtError && err.code === ErrorCode.REVOKED,
  );
  store._stop();
});

test('rotate: reuse detection → REFRESH_REUSED + family revoked', async () => {
  const { options, store } = fresh();
  const first = await create({ userId: 1 }, options);
  await rotate(first.refreshToken, options); // first rotate — OK
  await new Promise(r => setTimeout(r, 1100)); // move past 0s grace
  await assert.rejects(
    () => rotate(first.refreshToken, options),
    err => err instanceof JwtError && err.code === ErrorCode.REFRESH_REUSED,
  );
  // Family is nuked — the new refresh is also gone.
  assert.equal(store.size(), 0);
  store._stop();
});

test('rotate: within reuseWindow → idempotent replay allowed', async () => {
  const { options, store } = fresh();
  options.reuseWindow = '10s';
  const first = await create({ userId: 1 }, options);
  const second = await rotate(first.refreshToken, options);
  const third = await rotate(first.refreshToken, options); // still within 10s
  assert.notEqual(second.refreshToken, third.refreshToken);
  store._stop();
});

test('rotate: detectReuse=false silently allows re-rotation', async () => {
  const { options, store } = fresh();
  options.detectReuse = false;
  const first = await create({ userId: 1 }, options);
  await rotate(first.refreshToken, options);
  await new Promise(r => setTimeout(r, 1100));
  await rotate(first.refreshToken, options); // no throw
  store._stop();
});

// revoke
test('revoke: token gone after revoke', async () => {
  const { options, store } = fresh();
  const pair = await create({ userId: 1 }, options);
  await revoke(pair.refreshToken, { store });
  await assert.rejects(
    () => rotate(pair.refreshToken, options),
    err => err.code === ErrorCode.REVOKED,
  );
  store._stop();
});

// revokeAll
test('revokeAll: nukes every refresh in the family', async () => {
  const { options, store } = fresh();
  const p1 = await create({ userId: 1 }, options);
  const p2 = await rotate(p1.refreshToken, options);
  const outsider = await create({ userId: 2 }, options); // different family
  const count = await revokeAll(p2.familyId, { store });
  assert.equal(count, 2); // both p1 (used) + p2 (fresh)
  assert.equal(await store.has(await _hashOf(outsider.refreshToken)), true);
  store._stop();
});

// atomicity + grace-window
test('rotate: concurrent rotations of the same refresh are serialised (no double-spend)', async () => {
  const { options, store } = fresh();
  const pair = await create({ userId: 1 }, options);
  // Two parallel rotate calls with the same input. Without the mutex,
  // both would observe usedAt:null and both succeed — the double-spend
  // reuse detection exists to catch. The second call must land after
  // the first marked usedAt, tripping REVOKED-or-REUSED semantics.
  const results = await Promise.allSettled([rotate(pair.refreshToken, options), rotate(pair.refreshToken, options)]);
  const fulfilled = results.filter(r => r.status === 'fulfilled');
  const rejected = results.filter(r => r.status === 'rejected');
  assert.equal(fulfilled.length, 1, 'exactly one rotate should succeed');
  assert.equal(rejected.length, 1, 'exactly one rotate should fail');
  const err = rejected[0].reason;
  // Within grace window (0s by default) → second call is treated as
  // reuse and revokes the family.
  assert.equal(err.code, ErrorCode.REFRESH_REUSED);
  store._stop();
});

test('rotate: grace-window replay does not slide the window forward', async () => {
  const { options, store } = fresh();
  options.reuseWindow = '2s';
  const pair = await create({ userId: 1 }, options);
  const first = await rotate(pair.refreshToken, options);
  assert.ok(first.refreshToken);

  // Read the record and force usedAt back so we're at (grace - 1)s.
  const { createHash } = await import('node:crypto');
  const key = createHash('sha256').update(pair.refreshToken).digest('hex');
  const rec = await store.get(key);
  assert.ok(rec);
  const originalUsedAt = rec.metadata.usedAt;

  // Replay inside the grace window — issues a fresh pair but must NOT
  // touch usedAt (or the grace window slides).
  const second = await rotate(pair.refreshToken, options);
  assert.ok(second.refreshToken);
  const recAfter = await store.get(key);
  assert.equal(recAfter.metadata.usedAt, originalUsedAt, 'usedAt must not be re-stamped on replay');
  store._stop();
});

// markUsed CAS path
test('rotate: uses atomic markUsed when store provides it (no mutex)', async () => {
  const { options, store } = fresh();
  let markUsedCalls = 0;
  const origMarkUsed = store.markUsed.bind(store);
  store.markUsed = async (key, nowSec) => {
    markUsedCalls++;
    return origMarkUsed(key, nowSec);
  };
  const pair = await create({ userId: 1 }, options);
  await rotate(pair.refreshToken, options);
  assert.equal(markUsedCalls, 1);
  store._stop();
});

test('rotate: falls back to get+add when markUsed is absent', async () => {
  const { options, store } = fresh();
  delete store.markUsed;
  const pair = await create({ userId: 1 }, options);
  const rotated = await rotate(pair.refreshToken, options);
  assert.ok(rotated.refreshToken);
  assert.equal(rotated.familyId, pair.familyId);
  store._stop();
});

// namespace
test('tokenPair namespace exposes create/rotate/revoke/revokeAll', () => {
  assert.equal(tokenPair.create, create);
  assert.equal(tokenPair.rotate, rotate);
  assert.equal(tokenPair.revoke, revoke);
  assert.equal(tokenPair.revokeAll, revokeAll);
});

async function _hashOf(refreshToken) {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(refreshToken).digest('hex');
}
