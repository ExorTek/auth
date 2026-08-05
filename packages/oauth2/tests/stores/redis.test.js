// Redis-backed AS stores against an in-memory fake of the client contract
// (audit §4.2). The live-Redis pass is in redis.integration.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createRedisAuthCodeStore,
  createRedisRefreshStore,
  createRedisParStore,
  createRedisDeviceStore,
} from '../../src/server/index.js';

/** A minimal in-memory stand-in for ioredis / node-redis. */
function fakeClient() {
  const kv = new Map();
  const ttl = new Map();
  const sets = new Map();
  const live = k => {
    const t = ttl.get(k);
    if (t !== undefined && t <= Date.now()) {
      kv.delete(k);
      ttl.delete(k);
    }
    return kv.has(k);
  };
  return {
    async get(k) {
      return live(k) ? kv.get(k) : null;
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
    async mget(...keys) {
      return keys.map(k => (live(k) ? kv.get(k) : null));
    },
    async sadd(k, v) {
      let s = sets.get(k);
      if (!s) sets.set(k, (s = new Set()));
      s.add(v);
    },
    async srem(k, v) {
      sets.get(k)?.delete(v);
    },
    async smembers(k) {
      return [...(sets.get(k) ?? [])];
    },
  };
}

test('redis auth-code store: save then single-use consume', async () => {
  const store = createRedisAuthCodeStore(fakeClient());
  await store.save('code-1', { clientId: 'app', scope: ['read'] }, 60_000);
  const first = await store.consume('code-1');
  assert.equal(first.clientId, 'app');
  assert.equal(await store.consume('code-1'), undefined); // burned
});

test('redis PAR store: pushed params round-trip once', async () => {
  const store = createRedisParStore(fakeClient());
  await store.save('urn:req:1', { client_id: 'app' }, 90_000);
  assert.deepEqual(await store.consume('urn:req:1'), { client_id: 'app' });
  assert.equal(await store.consume('urn:req:1'), undefined);
});

test('redis refresh store: rotate marks used and revokeFamily burns the family', async () => {
  const store = createRedisRefreshStore(fakeClient());
  const base = { familyId: 'f1', clientId: 'app', scope: ['read'], expiresAt: Date.now() + 60_000 };
  await store.save({ ...base, token: 't1' });
  await store.rotate('t1', { ...base, token: 't2' });
  assert.equal((await store.get('t1')).used, true);
  assert.equal((await store.get('t2')).used, undefined);

  await store.revokeFamily('f1');
  assert.equal((await store.get('t2')).revoked, true);
});

test('redis refresh store: an expired record reads as absent', async () => {
  const store = createRedisRefreshStore(fakeClient());
  await store.save({ token: 't1', familyId: 'f1', clientId: 'app', scope: [], expiresAt: Date.now() - 1 });
  assert.equal(await store.get('t1'), null);
});

test('redis device store: device/user code lookup and redemption cleans the reverse index', async () => {
  const client = fakeClient();
  const store = createRedisDeviceStore(client);
  await store.save({ deviceCode: 'd1', userCode: 'ABCD-EFGH', clientId: 'app', scope: [], status: 'pending' }, 600_000);
  assert.equal((await store.getByUserCode('ABCD-EFGH')).deviceCode, 'd1');

  await store.update('d1', { status: 'approved', subject: 'user-1' });
  assert.equal((await store.getByDeviceCode('d1')).subject, 'user-1');

  await store.update('d1', { status: 'redeemed' });
  assert.equal(await store.getByUserCode('ABCD-EFGH'), undefined); // reverse index freed
});
