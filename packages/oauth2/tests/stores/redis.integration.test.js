// Live-Redis pass for the AS stores (audit §4.2). Skipped unless REDIS_URL
// is set:  REDIS_URL=redis://localhost:6379 yarn workspace @exortek/oauth2 test
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

import { createRedisAuthCodeStore, createRedisRefreshStore, createRedisDeviceStore } from '../../src/server/index.js';

const REDIS_URL = process.env.REDIS_URL;
const suite = REDIS_URL ? test : test.skip;

let client;

before(async () => {
  if (!REDIS_URL) return;
  const { createClient } = await import('redis');
  client = createClient({ url: REDIS_URL });
  await client.connect();
});

after(async () => {
  if (client) await client.quit();
});

suite('live redis: auth-code single-use consume', async () => {
  const store = createRedisAuthCodeStore(client, { keyPrefix: `oauth2:test:${Date.now()}:` });
  await store.save('c1', { clientId: 'app', scope: ['read'] }, 5_000);
  assert.equal((await store.consume('c1')).clientId, 'app');
  assert.equal(await store.consume('c1'), undefined);
});

suite('live redis: refresh rotate + revokeFamily', async () => {
  const store = createRedisRefreshStore(client, { keyPrefix: `oauth2:test:${Date.now()}:` });
  const base = { familyId: 'f1', clientId: 'app', scope: [], expiresAt: Date.now() + 5_000 };
  await store.save({ ...base, token: 't1' });
  await store.rotate('t1', { ...base, token: 't2' });
  assert.equal((await store.get('t1')).used, true);
  await store.revokeFamily('f1');
  assert.equal((await store.get('t2')).revoked, true);
});

suite('live redis: device lookup + reverse-index cleanup', async () => {
  const store = createRedisDeviceStore(client, { keyPrefix: `oauth2:test:${Date.now()}:` });
  await store.save({ deviceCode: 'd1', userCode: 'WXYZ-2345', clientId: 'app', scope: [], status: 'pending' }, 5_000);
  assert.equal((await store.getByUserCode('WXYZ-2345')).deviceCode, 'd1');
  await store.update('d1', { status: 'redeemed' });
  assert.equal(await store.getByUserCode('WXYZ-2345'), undefined);
});
