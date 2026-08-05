// Live-Redis pass for the AS stores (audit §4.2). Skipped unless REDIS_URL
// is set:  REDIS_URL=redis://localhost:6379 yarn workspace @exortek/oauth2 test
import { test, after } from 'node:test';
import assert from 'node:assert/strict';

import { createRedisAuthCodeStore, createRedisRefreshStore, createRedisDeviceStore } from '../../src/server/index.js';

const REDIS_URL = process.env.REDIS_URL;
let ioredis;
try {
  ioredis = (await import('ioredis')).default;
} catch {
  ioredis = null;
}

const skip = !REDIS_URL
  ? 'REDIS_URL not set — skipping integration tests'
  : !ioredis
    ? 'ioredis not installed — skipping integration tests'
    : false;

let sharedClient = null;
function client() {
  if (!sharedClient) sharedClient = new ioredis(REDIS_URL, { lazyConnect: true });
  return sharedClient;
}
const prefix = () => `oauth2:test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}:`;

after(() => sharedClient?.quit());

test('live redis: auth-code single-use consume', { skip }, async () => {
  const store = createRedisAuthCodeStore(client(), { keyPrefix: prefix() });
  await store.save('c1', { clientId: 'app', scope: ['read'] }, 5_000);
  assert.equal((await store.consume('c1')).clientId, 'app');
  assert.equal(await store.consume('c1'), undefined);
});

test('live redis: refresh rotate + revokeFamily', { skip }, async () => {
  const store = createRedisRefreshStore(client(), { keyPrefix: prefix() });
  const base = { familyId: 'f1', clientId: 'app', scope: [], expiresAt: Date.now() + 5_000 };
  await store.save({ ...base, token: 't1' });
  await store.rotate('t1', { ...base, token: 't2' });
  assert.equal((await store.get('t1')).used, true);
  await store.revokeFamily('f1');
  assert.equal((await store.get('t2')).revoked, true);
});

test('live redis: an expired refresh record reads as absent', { skip }, async () => {
  const store = createRedisRefreshStore(client(), { keyPrefix: prefix() });
  await store.save({ token: 't1', familyId: 'f1', clientId: 'app', scope: [], expiresAt: Date.now() - 1 });
  assert.equal(await store.get('t1'), null);
});

test('live redis: device lookup + reverse-index cleanup', { skip }, async () => {
  const store = createRedisDeviceStore(client(), { keyPrefix: prefix() });
  await store.save({ deviceCode: 'd1', userCode: 'WXYZ-2345', clientId: 'app', scope: [], status: 'pending' }, 5_000);
  assert.equal((await store.getByUserCode('WXYZ-2345')).deviceCode, 'd1');
  await store.update('d1', { status: 'redeemed' });
  assert.equal(await store.getByUserCode('WXYZ-2345'), undefined);
});
