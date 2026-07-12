import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rateLimit } from '../src/index.js';
import { parseDuration } from '../src/rate-limit/duration.js';
import { SecurityError } from '../src/index.js';

test('parseDuration accepts numbers as ms', () => {
  assert.equal(parseDuration(1000), 1000);
  assert.equal(parseDuration(1), 1);
});

test('parseDuration accepts duration strings', () => {
  assert.equal(parseDuration('500ms'), 500);
  assert.equal(parseDuration('30s'), 30_000);
  assert.equal(parseDuration('15m'), 15 * 60_000);
  assert.equal(parseDuration('1h'), 60 * 60_000);
  assert.equal(parseDuration('7d'), 7 * 24 * 60 * 60_000);
  assert.equal(parseDuration('2w'), 2 * 7 * 24 * 60 * 60_000);
});

test('parseDuration is case-insensitive', () => {
  assert.equal(parseDuration('30S'), 30_000);
  assert.equal(parseDuration('1H'), 3_600_000);
});

test('parseDuration rejects zero, negative, non-integer numbers', () => {
  assert.throws(() => parseDuration(0), SecurityError);
  assert.throws(() => parseDuration(-1), SecurityError);
  assert.throws(() => parseDuration(1.5), SecurityError);
  assert.throws(() => parseDuration(NaN), SecurityError);
});

test('parseDuration rejects malformed strings', () => {
  assert.throws(() => parseDuration(''), SecurityError);
  assert.throws(() => parseDuration('nonsense'), SecurityError);
  assert.throws(() => parseDuration('10x'), SecurityError);
  assert.throws(() => parseDuration('m'), SecurityError);
});

test('parseDuration includes field name in error', () => {
  try {
    parseDuration('bad', 'refillRate');
    assert.fail('should throw');
  } catch (err) {
    assert.ok(err.message.includes('refillRate'));
  }
});

test('memoryStore: incr increments and returns count/expiresAt', async () => {
  const store = rateLimit.stores.memory();
  const a = await store.incr('k', 1000);
  const b = await store.incr('k', 1000);
  assert.equal(a.count, 1);
  assert.equal(b.count, 2);
  assert.ok(a.expiresAt > Date.now());
  store._stop();
});

test('memoryStore: get returns null for missing keys', async () => {
  const store = rateLimit.stores.memory();
  assert.equal(await store.get('missing'), null);
  store._stop();
});

test('memoryStore: expired entries are removed lazily', async () => {
  const store = rateLimit.stores.memory();
  await store.incr('k', 10);
  await new Promise(r => setTimeout(r, 20));
  assert.equal(await store.get('k'), null);
  store._stop();
});

test('memoryStore: read is non-mutating alias of get', async () => {
  const store = rateLimit.stores.memory();
  await store.incr('k', 1000);
  const a = await store.read('k');
  const b = await store.read('k');
  assert.equal(a.count, 1);
  assert.equal(b.count, 1);
  store._stop();
});

test('memoryStore: LRU evicts oldest when full', async () => {
  const store = rateLimit.stores.memory({ maxKeys: 3 });
  await store.incr('a', 60_000);
  await store.incr('b', 60_000);
  await store.incr('c', 60_000);
  await store.incr('d', 60_000);
  assert.equal(await store.read('a'), null);
  assert.ok(await store.read('d'));
  store._stop();
});

test('memoryStore: access refreshes LRU position — hot key survives eviction', async () => {
  // Insertion order: a, b, c. Touch `a` (making b the LRU), then insert d.
  // With insertion-order eviction, `a` would be dropped. True LRU drops `b`.
  const store = rateLimit.stores.memory({ maxKeys: 3 });
  await store.incr('a', 60_000);
  await store.incr('b', 60_000);
  await store.incr('c', 60_000);
  await store.incr('a', 60_000); // touch — refreshes LRU
  await store.incr('d', 60_000); // cap hit; evicts LRU

  assert.ok(await store.read('a'), 'hot key `a` must survive eviction');
  assert.equal(await store.read('b'), null, 'least-recently-used `b` must be evicted');
  assert.ok(await store.read('c'));
  assert.ok(await store.read('d'));
  store._stop();
});

test('memoryStore: read() does NOT refresh LRU position', async () => {
  // If read touched LRU, `a` would survive. It must not.
  const store = rateLimit.stores.memory({ maxKeys: 3 });
  await store.incr('a', 60_000);
  await store.incr('b', 60_000);
  await store.incr('c', 60_000);
  await store.read('a'); // introspection — must not shift order
  await store.incr('d', 60_000);
  assert.equal(await store.read('a'), null, 'read must not keep `a` alive');
  store._stop();
});

test('memoryStore: get() refreshes LRU position', async () => {
  const store = rateLimit.stores.memory({ maxKeys: 3 });
  await store.incr('a', 60_000);
  await store.incr('b', 60_000);
  await store.incr('c', 60_000);
  await store.get('a'); // activity — should refresh
  await store.incr('d', 60_000);
  assert.ok(await store.read('a'), '`a` must survive because get() refreshed it');
  assert.equal(await store.read('b'), null);
  store._stop();
});

test('memoryStore: set() overwrite refreshes LRU position', async () => {
  const store = rateLimit.stores.memory({ maxKeys: 3 });
  await store.incr('a', 60_000);
  await store.incr('b', 60_000);
  await store.incr('c', 60_000);
  await store.set('a', 5, 60_000); // overwrite — moves to newest
  await store.incr('d', 60_000);
  const a = await store.read('a');
  assert.ok(a, '`a` must survive because set() moved it to newest');
  assert.equal(a.count, 5);
  assert.equal(await store.read('b'), null);
  store._stop();
});

test('memoryStore: reset clears a key', async () => {
  const store = rateLimit.stores.memory();
  await store.incr('k', 60_000);
  await store.reset('k');
  assert.equal(await store.get('k'), null);
  store._stop();
});

test('memoryStore: rejects invalid maxKeys/sweepMs', () => {
  assert.throws(() => rateLimit.stores.memory({ maxKeys: 0 }), TypeError);
  assert.throws(() => rateLimit.stores.memory({ sweepMs: 100 }), TypeError);
});

test('customStore: validates required methods', () => {
  assert.throws(() => rateLimit.stores.custom(null), SecurityError);
  assert.throws(() => rateLimit.stores.custom({}), SecurityError);
  assert.throws(() => rateLimit.stores.custom({ get: () => {}, incr: () => {}, set: () => {} }), SecurityError);
});

test('customStore: read falls back to get when omitted', async () => {
  let getCalls = 0;
  const store = rateLimit.stores.custom({
    get: () => {
      getCalls += 1;
      return null;
    },
    incr: () => ({ count: 1, expiresAt: Date.now() + 1000 }),
    set: () => {},
    delete: () => {},
  });
  await store.read('k');
  assert.equal(getCalls, 1);
});

test('customStore: reset falls back to delete when omitted', async () => {
  let deleteCalls = 0;
  const store = rateLimit.stores.custom({
    get: () => null,
    incr: () => ({ count: 1, expiresAt: Date.now() + 1000 }),
    set: () => {},
    delete: () => {
      deleteCalls += 1;
    },
  });
  await store.reset('k');
  assert.equal(deleteCalls, 1);
});

test('fixed: allows up to limit, then denies', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.fixed({ requests: 3, window: '1m', store });
  const r1 = await limiter.check({ key: 'ip:1' });
  const r2 = await limiter.check({ key: 'ip:1' });
  const r3 = await limiter.check({ key: 'ip:1' });
  const r4 = await limiter.check({ key: 'ip:1' });
  assert.equal(r1.allowed, true);
  assert.equal(r1.remaining, 2);
  assert.equal(r2.allowed, true);
  assert.equal(r2.remaining, 1);
  assert.equal(r3.allowed, true);
  assert.equal(r3.remaining, 0);
  assert.equal(r4.allowed, false);
  assert.ok(r4.retryAfter >= 1);
  store._stop();
});

test('fixed: isolates by key', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.fixed({ requests: 1, window: '1m', store });
  const a = await limiter.check({ key: 'a' });
  const b = await limiter.check({ key: 'b' });
  assert.equal(a.allowed, true);
  assert.equal(b.allowed, true);
  store._stop();
});

test('fixed: reset is a Date in the future', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.fixed({ requests: 1, window: '1m', store });
  const r = await limiter.check({ key: 'k' });
  assert.ok(r.reset instanceof Date);
  assert.ok(r.reset.getTime() > Date.now());
  store._stop();
});

test('fixed: rejects missing key', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.fixed({ requests: 1, window: '1m', store });
  await assert.rejects(() => limiter.check({}), SecurityError);
  await assert.rejects(() => limiter.check({ key: '' }), SecurityError);
  store._stop();
});

test('sliding: allows up to limit, then denies', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.sliding({ requests: 3, window: '1m', store });
  const r1 = await limiter.check({ key: 'k' });
  const r2 = await limiter.check({ key: 'k' });
  const r3 = await limiter.check({ key: 'k' });
  const r4 = await limiter.check({ key: 'k' });
  assert.equal(r1.allowed, true);
  assert.equal(r2.allowed, true);
  assert.ok(r2.remaining < r1.remaining);
  assert.equal(r3.allowed, true);
  assert.equal(r4.allowed, false);
  store._stop();
});

test('sliding: rolls back counter on denial so remaining stays consistent', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.sliding({ requests: 2, window: '1m', store });
  await limiter.check({ key: 'k' });
  await limiter.check({ key: 'k' });
  const denied = await limiter.check({ key: 'k' });
  const denied2 = await limiter.check({ key: 'k' });
  assert.equal(denied.allowed, false);
  assert.equal(denied2.allowed, false);
  store._stop();
});

test('tokenBucket: allows burst up to capacity', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.tokenBucket({ capacity: 5, refillRate: 1, store });
  const results = [];
  for (let i = 0; i < 6; i++) {
    results.push(await limiter.check({ key: 'k' }));
  }
  const allowed = results.filter(r => r.allowed).length;
  const denied = results.filter(r => !r.allowed).length;
  assert.equal(allowed, 5);
  assert.equal(denied, 1);
  store._stop();
});

test('tokenBucket: refills tokens over time', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.tokenBucket({ capacity: 2, refillRate: 100, store });
  await limiter.check({ key: 'k' });
  await limiter.check({ key: 'k' });
  const denied = await limiter.check({ key: 'k' });
  assert.equal(denied.allowed, false);
  await new Promise(r => setTimeout(r, 50));
  const allowed = await limiter.check({ key: 'k' });
  assert.equal(allowed.allowed, true);
  store._stop();
});

test('tokenBucket: retryAfter reflects deficit', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.tokenBucket({ capacity: 1, refillRate: 1, store });
  await limiter.check({ key: 'k' });
  const denied = await limiter.check({ key: 'k' });
  assert.equal(denied.allowed, false);
  assert.ok(denied.retryAfter >= 1);
  store._stop();
});

test('leakyBucket: rejects when full', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.leakyBucket({ capacity: 3, leakRate: 1, store });
  const r1 = await limiter.check({ key: 'k' });
  const r2 = await limiter.check({ key: 'k' });
  const r3 = await limiter.check({ key: 'k' });
  const r4 = await limiter.check({ key: 'k' });
  assert.equal(r1.allowed, true);
  assert.equal(r2.allowed, true);
  assert.equal(r3.allowed, true);
  assert.equal(r4.allowed, false);
  assert.equal(r4.remaining, 0);
  store._stop();
});

test('leakyBucket: drains over time', async () => {
  const store = rateLimit.stores.memory();
  const limiter = rateLimit.leakyBucket({ capacity: 2, leakRate: 100, store });
  await limiter.check({ key: 'k' });
  await limiter.check({ key: 'k' });
  const denied = await limiter.check({ key: 'k' });
  assert.equal(denied.allowed, false);
  await new Promise(r => setTimeout(r, 30));
  const allowed = await limiter.check({ key: 'k' });
  assert.equal(allowed.allowed, true);
  store._stop();
});

test('multi: denies when any inner limiter denies', async () => {
  const store = rateLimit.stores.memory();
  const perMin = rateLimit.fixed({ requests: 10, window: '1m', store });
  const perSec = rateLimit.fixed({ requests: 1, window: '1s', store });
  const combined = rateLimit.multi({ limiters: [perMin, perSec] });

  const r1 = await combined.check({ key: 'k' });
  const r2 = await combined.check({ key: 'k' });
  assert.equal(r1.allowed, true);
  assert.equal(r2.allowed, false);
  store._stop();
});

test('multi: allows when all inner limiters allow', async () => {
  const store = rateLimit.stores.memory();
  const a = rateLimit.fixed({ requests: 10, window: '1m', store });
  const b = rateLimit.fixed({ requests: 10, window: '1h', store });
  const combined = rateLimit.multi({ limiters: [a, b] });
  const r = await combined.check({ key: 'k' });
  assert.equal(r.allowed, true);
  store._stop();
});

test('multi: uses max retryAfter across deniers', async () => {
  const denyShort = {
    async check() {
      return { allowed: false, remaining: 0, reset: null, retryAfter: 2 };
    },
  };
  const denyLong = {
    async check() {
      return { allowed: false, remaining: 0, reset: null, retryAfter: 60 };
    },
  };
  const combined = rateLimit.multi({ limiters: [denyShort, denyLong] });
  const r = await combined.check({ key: 'k' });
  assert.equal(r.allowed, false);
  assert.equal(r.retryAfter, 60);
});

test('multi: rejects empty limiters array', () => {
  assert.throws(() => rateLimit.multi({ limiters: [] }), SecurityError);
  assert.throws(() => rateLimit.multi({}), SecurityError);
});

test('multi: rejects limiters missing check()', () => {
  assert.throws(() => rateLimit.multi({ limiters: [{ check: () => {} }, {}] }), SecurityError);
});

test('fixed: rejects missing store or requests', () => {
  assert.throws(() => rateLimit.fixed({ requests: 5, window: '1m' }), SecurityError);
  assert.throws(() => rateLimit.fixed({ window: '1m', store: rateLimit.stores.memory() }), SecurityError);
});

test('tokenBucket: rejects missing capacity or refillRate', () => {
  const store = rateLimit.stores.memory();
  assert.throws(() => rateLimit.tokenBucket({ refillRate: 1, store }), SecurityError);
  assert.throws(() => rateLimit.tokenBucket({ capacity: 5, store }), SecurityError);
  store._stop();
});

// redis store (via a mock client)
//
// We don't spin up a real Redis in unit tests. Instead we fake the two
// clients we support — ioredis (`defineCommand`) and node-redis (options-
// object `eval`) — and assert both paths compile the same result. The
// scripts themselves run against a tiny in-memory kv, not the real Redis
// interpreter, so the tests verify wire-up and result parsing, not the Lua.

function fakeIoredisClient() {
  const kv = new Map();
  const client = {
    _kv: kv,
    _commands: {},
    async get(key) {
      const e = kv.get(key);
      return e && e.expiresAt > Date.now() ? String(e.count) : null;
    },
    async set(key, value, _px, ttl) {
      kv.set(key, { count: Number(value), expiresAt: Date.now() + ttl });
      return 'OK';
    },
    async del(key) {
      const had = kv.has(key);
      kv.delete(key);
      return had ? 1 : 0;
    },
    async eval(_script, _n, ..._rest) {
      throw new Error('should have used defineCommand path');
    },
    defineCommand(name, spec) {
      client._commands[name] = spec;
      client[name] = async (fullKey, arg) => {
        if (name === 'exortekRlIncr') {
          const ttlMs = Number(arg);
          const existing = kv.get(fullKey);
          if (!existing || existing.expiresAt <= Date.now()) {
            kv.set(fullKey, { count: 1, expiresAt: Date.now() + ttlMs });
            return [1, ttlMs];
          }
          existing.count += 1;
          return [existing.count, existing.expiresAt - Date.now()];
        }
        // exortekRlRead
        const e = kv.get(fullKey);
        if (!e || e.expiresAt <= Date.now()) {
          return [0, -1];
        }
        return [e.count, e.expiresAt - Date.now()];
      };
    },
  };
  return client;
}

function fakeNodeRedisClient() {
  const kv = new Map();
  return {
    _kv: kv,
    async get(key) {
      const e = kv.get(key);
      return e && e.expiresAt > Date.now() ? String(e.count) : null;
    },
    async set(key, value, _px, ttl) {
      kv.set(key, { count: Number(value), expiresAt: Date.now() + ttl });
      return 'OK';
    },
    async del(key) {
      kv.delete(key);
      return 1;
    },
    // node-redis v4-style: eval(script, { keys, arguments })
    // Simulate INCR/READ script semantics.
    sendCommand: () => {}, // marker for node-redis path
    async eval(script, opts) {
      const key = opts.keys[0];
      if (script.includes('INCR')) {
        const ttlMs = Number(opts.arguments[0]);
        const existing = kv.get(key);
        if (!existing || existing.expiresAt <= Date.now()) {
          kv.set(key, { count: 1, expiresAt: Date.now() + ttlMs });
          return [1, ttlMs];
        }
        existing.count += 1;
        return [existing.count, existing.expiresAt - Date.now()];
      }
      // READ_SCRIPT
      const e = kv.get(key);
      if (!e || e.expiresAt <= Date.now()) {
        return [0, -1];
      }
      return [e.count, e.expiresAt - Date.now()];
    },
  };
}

test('redisStore: rejects non-Redis clients', () => {
  assert.throws(() => rateLimit.stores.redis(null), SecurityError);
  assert.throws(() => rateLimit.stores.redis({}), SecurityError);
});

test('redisStore: incr/get roundtrip (ioredis path with defineCommand)', async () => {
  const client = fakeIoredisClient();
  const store = rateLimit.stores.redis(client);
  const a = await store.incr('user:1', 1000);
  const b = await store.incr('user:1', 1000);
  assert.equal(a.count, 1);
  assert.equal(b.count, 2);
  assert.ok(a.expiresAt > Date.now());
  assert.ok(client._commands.exortekRlIncr);
  assert.ok(client._commands.exortekRlRead);
});

test('redisStore: read is non-mutating (ioredis path)', async () => {
  const client = fakeIoredisClient();
  const store = rateLimit.stores.redis(client);
  await store.incr('k', 1000);
  const a = await store.read('k');
  const b = await store.read('k');
  assert.equal(a.count, 1);
  assert.equal(b.count, 1);
});

test('redisStore: read returns null for missing keys', async () => {
  const client = fakeIoredisClient();
  const store = rateLimit.stores.redis(client);
  assert.equal(await store.read('missing'), null);
  assert.equal(await store.get('missing'), null);
});

test('redisStore: uses eval fallback on node-redis clients', async () => {
  const client = fakeNodeRedisClient();
  const store = rateLimit.stores.redis(client);
  const a = await store.incr('k', 1000);
  const b = await store.incr('k', 1000);
  assert.equal(a.count, 1);
  assert.equal(b.count, 2);
  const r = await store.read('k');
  assert.equal(r.count, 2);
});

test('redisStore: keys are namespaced by prefix', async () => {
  const client = fakeIoredisClient();
  const store = rateLimit.stores.redis(client, { prefix: 'app:rl:' });
  await store.incr('user:1', 1000);
  assert.ok(client._kv.has('app:rl:user:1'));
});

test('redisStore: works end-to-end with fixed limiter', async () => {
  const client = fakeIoredisClient();
  const store = rateLimit.stores.redis(client);
  const limiter = rateLimit.fixed({ requests: 2, window: '1m', store });
  const r1 = await limiter.check({ key: 'ip' });
  const r2 = await limiter.check({ key: 'ip' });
  const r3 = await limiter.check({ key: 'ip' });
  assert.equal(r1.allowed, true);
  assert.equal(r2.allowed, true);
  assert.equal(r3.allowed, false);
});
