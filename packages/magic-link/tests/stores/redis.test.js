import { test } from 'node:test';
import assert from 'node:assert/strict';

import { redisStore } from '../../src/stores/redis.js';
import { MagicLinkError, ErrorCode } from '../../src/index.js';

/**
 * Minimal in-memory fake of ioredis's contract. Enough of `eval` to
 * run the CONSUME_SCRIPT semantics and the INCR_RATE_SCRIPT semantics
 * without a live Redis. We simulate cjson.decode/encode as
 * JSON.parse/stringify.
 */
function fakeClient() {
  const kv = new Map();
  const ttl = new Map();
  const sets = new Map();
  return {
    kv,
    sets,
    async get(k) {
      const t = ttl.get(k);
      if (t !== undefined && t <= Date.now()) {
        kv.delete(k);
        ttl.delete(k);
      }
      return kv.has(k) ? kv.get(k) : null;
    },
    async set(k, v, ...rest) {
      kv.set(k, v);
      const ix = rest.indexOf('PX');
      if (ix !== -1) ttl.set(k, Date.now() + Number(rest[ix + 1]));
    },
    async del(k) {
      kv.delete(k);
      ttl.delete(k);
    },
    async sadd(k, v) {
      let s = sets.get(k);
      if (!s) {
        s = new Set();
        sets.set(k, s);
      }
      s.add(v);
    },
    async srem(k, v) {
      const s = sets.get(k);
      if (s) s.delete(v);
    },
    async smembers(k) {
      const s = sets.get(k);
      return s ? [...s] : [];
    },
    async mget(...keys) {
      return keys.map(k => (kv.has(k) ? kv.get(k) : null));
    },
    async eval(script, _numKeys, ...args) {
      // CONSUME_SCRIPT — flips consumedAt in-place.
      if (script.includes('record.consumedAt = now')) {
        const key = args[0];
        const now = Number(args[1]);
        const raw = kv.get(key);
        if (!raw) return 0;
        const record = JSON.parse(raw);
        if (record.consumedAt) return 0;
        record.consumedAt = now;
        kv.set(key, JSON.stringify(record));
        return 1;
      }
      // INCR_RATE_SCRIPT — INCR + PEXPIRE on first hit.
      if (script.includes("redis.call('INCR', key)")) {
        const key = args[0];
        const ttlMs = Number(args[1]);
        const now = Date.now();
        const existing = kv.get(key);
        if (existing === undefined || (ttl.get(key) ?? 0) <= now) {
          kv.set(key, '1');
          ttl.set(key, now + ttlMs);
          return [1, ttlMs];
        }
        const next = Number(existing) + 1;
        kv.set(key, String(next));
        return [next, (ttl.get(key) ?? now + ttlMs) - now];
      }
      return null;
    },
  };
}

function newRecord(id, email) {
  return {
    id,
    email,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
  };
}

test('rejects a client that lacks the required methods', () => {
  assert.throws(
    () => redisStore({}),
    err => err instanceof MagicLinkError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('put + getById against a fake ioredis client', async () => {
  const store = redisStore(fakeClient());
  await store.put(newRecord('id1', 'a@x.com'));
  const back = await store.getById('id1');
  assert.equal(back.id, 'id1');
  assert.equal(back.email, 'a@x.com');
});

test('consume: atomic — second call returns false', async () => {
  const store = redisStore(fakeClient());
  await store.put(newRecord('id1', 'a@x.com'));
  assert.equal(await store.consume('id1'), true);
  assert.equal(await store.consume('id1'), false);
});

test('listByEmail: prunes dead index references', async () => {
  const client = fakeClient();
  const store = redisStore(client);
  await store.put(newRecord('alive', 'u@x.com'));
  await client.sadd('mlink:e:u@x.com', 'ghost');
  const rows = await store.listByEmail('u@x.com');
  const ids = rows.map(r => r.id);
  assert.deepEqual(ids, ['alive']);
});

test('revokeByEmail: returns count of newly-consumed records', async () => {
  const store = redisStore(fakeClient());
  await store.put(newRecord('a', 'u@x.com'));
  await store.put(newRecord('b', 'u@x.com'));
  await store.consume('a'); // already used
  const n = await store.revokeByEmail('u@x.com');
  assert.equal(n, 1);
});

test('incrRate: first call count=1, second count=2', async () => {
  const store = redisStore(fakeClient());
  const a = await store.incrRate('u@x.com', 60_000);
  const b = await store.incrRate('u@x.com', 60_000);
  assert.equal(a.count, 1);
  assert.equal(b.count, 2);
});

test('keyPrefix override: prepended everywhere', async () => {
  const client = fakeClient();
  const store = redisStore(client, { keyPrefix: 'myapp:mlink:' });
  await store.put(newRecord('id1', 'a@x.com'));
  assert.ok(client.kv.has('myapp:mlink:id1'));
  assert.ok(client.sets.has('myapp:mlink:e:a@x.com'));
});
