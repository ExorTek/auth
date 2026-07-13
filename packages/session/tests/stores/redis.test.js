import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redisStore } from '../../src/stores/redis.js';

// Fake ioredis client — implements the minimum surface redisStore uses.
// Deliberately in-memory; matches the string-args SET signature.
function fakeIoredis() {
  const kv = new Map();
  const sets = new Map();
  const published = [];
  return {
    async get(key) {
      const entry = kv.get(key);
      if (!entry) return null;
      if (entry.expiresAt <= Date.now()) {
        kv.delete(key);
        return null;
      }
      return entry.value;
    },
    async set(key, value, ...rest) {
      let px = 0;
      for (let i = 0; i < rest.length; i++) {
        if (rest[i] === 'PX' && typeof rest[i + 1] === 'number') {
          px = rest[i + 1];
        }
      }
      kv.set(key, { value, expiresAt: Date.now() + (px || 60_000) });
      return 'OK';
    },
    async del(key) {
      return kv.delete(key) ? 1 : 0;
    },
    async sadd(key, member) {
      let set = sets.get(key);
      if (!set) {
        set = new Set();
        sets.set(key, set);
      }
      set.add(member);
      return 1;
    },
    async srem(key, member) {
      const set = sets.get(key);
      if (!set) return 0;
      return set.delete(member) ? 1 : 0;
    },
    async smembers(key) {
      const set = sets.get(key);
      return set ? [...set] : [];
    },
    async publish(channel, message) {
      published.push({ channel, message });
      return 1;
    },
    get __published() {
      return published;
    },
  };
}

function makeRecord(overrides = {}) {
  const now = Date.now();
  return {
    sid: overrides.sid ?? 's1',
    uid: overrides.uid ?? 'u1',
    claims: overrides.claims ?? {},
    issuedAt: now,
    expiresAt: overrides.expiresAt ?? now + 60_000,
    lastSeenAt: overrides.lastSeenAt ?? now,
    isAnonymous: overrides.uid === null,
    revoked: false,
    ...overrides,
  };
}

test('redisStore: put + get round trip', async () => {
  const store = redisStore(fakeIoredis());
  const rec = makeRecord({ sid: 'a' });
  await store.put(rec);
  const got = await store.get('a');
  assert.equal(got.sid, 'a');
  assert.equal(got.uid, 'u1');
});

test('redisStore: revoke marks the record', async () => {
  const store = redisStore(fakeIoredis());
  await store.put(makeRecord({ sid: 'a' }));
  assert.equal(await store.revoke('a', 'logout'), true);
  const got = await store.get('a');
  assert.equal(got.revoked, true);
  assert.equal(got.revokedReason, 'logout');
});

test('redisStore: revokeAllForUser kills every session', async () => {
  const store = redisStore(fakeIoredis());
  await store.put(makeRecord({ sid: 'a', uid: 'u1' }));
  await store.put(makeRecord({ sid: 'b', uid: 'u1' }));
  await store.put(makeRecord({ sid: 'c', uid: 'u2' }));
  assert.equal(await store.revokeAllForUser('u1'), 2);
  assert.equal((await store.get('a')).revoked, true);
  assert.equal((await store.get('c')).revoked, false);
});

test('redisStore: revokeAllExcept preserves keepSid', async () => {
  const store = redisStore(fakeIoredis());
  await store.put(makeRecord({ sid: 'a', uid: 'u1' }));
  await store.put(makeRecord({ sid: 'b', uid: 'u1' }));
  await store.put(makeRecord({ sid: 'c', uid: 'u1' }));
  assert.equal(await store.revokeAllExcept('u1', 'b'), 2);
  assert.equal((await store.get('a')).revoked, true);
  assert.equal((await store.get('b')).revoked, false);
  assert.equal((await store.get('c')).revoked, true);
});

test('redisStore: listByUser returns non-revoked newest-first', async () => {
  const store = redisStore(fakeIoredis());
  await store.put(makeRecord({ sid: 'old', uid: 'u1', lastSeenAt: 1000 }));
  await store.put(makeRecord({ sid: 'new', uid: 'u1', lastSeenAt: 5000 }));
  const bad = makeRecord({ sid: 'bad', uid: 'u1' });
  await store.put(bad);
  await store.revoke('bad');
  const list = await store.listByUser('u1');
  assert.deepEqual(list.map(r => r.sid), ['new', 'old']);
});

test('redisStore: countActive skips revoked', async () => {
  const store = redisStore(fakeIoredis());
  await store.put(makeRecord({ sid: 'a', uid: 'u1' }));
  const b = makeRecord({ sid: 'b', uid: 'u1' });
  await store.put(b);
  await store.revoke('b');
  assert.equal(await store.countActive('u1'), 1);
});

test('redisStore: publishRevocations emits to channel', async () => {
  const client = fakeIoredis();
  const store = redisStore(client, { publishRevocations: true });
  await store.put(makeRecord({ sid: 'a' }));
  await store.revoke('a', 'logout');
  const published = client.__published;
  assert.equal(published.length, 1);
  const msg = JSON.parse(published[0].message);
  assert.equal(msg.type, 'revoke');
  assert.equal(msg.sid, 'a');
  assert.equal(msg.reason, 'logout');
});

test('redisStore: works with node-redis camelCase methods', async () => {
  const kv = new Map();
  const sets = new Map();
  const client = {
    async get(key) {
      return kv.get(key) ?? null;
    },
    async set(key, value, opts) {
      kv.set(key, value);
      return 'OK';
    },
    async del(key) {
      return kv.delete(key) ? 1 : 0;
    },
    async sAdd(key, member) {
      let set = sets.get(key);
      if (!set) {
        set = new Set();
        sets.set(key, set);
      }
      set.add(member);
      return 1;
    },
    async sMembers(key) {
      const set = sets.get(key);
      return set ? [...set] : [];
    },
    async sRem(key, member) {
      const set = sets.get(key);
      if (!set) return 0;
      return set.delete(member) ? 1 : 0;
    },
  };
  const store = redisStore(client);
  await store.put(makeRecord({ sid: 'a', uid: 'u1' }));
  assert.equal((await store.get('a')).sid, 'a');
  assert.equal(await store.countActive('u1'), 1);
});

test('redisStore: rejects a client that is missing get/set/del', () => {
  assert.throws(() => redisStore({}));
  assert.throws(() => redisStore({ get: async () => null }));
});
