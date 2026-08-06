/**
 * Live-Redis pass for the authorization-server stores, run against both
 * supported clients. Skipped unless REDIS_URL is set:
 *
 *   REDIS_URL=redis://localhost:6379 yarn workspace @exortek/oauth2 test
 */

import assert from 'node:assert/strict';

import { forEachRedisDriver } from '@exortek/shared/test-helpers/redis-drivers';

import { createRedisAuthCodeStore, createRedisRefreshStore, createRedisDeviceStore } from '../../src/server/index.js';

forEachRedisDriver('oauth2 server stores', ({ test, client, ns, raw }) => {
  test('auth-code single-use consume', async () => {
    const store = createRedisAuthCodeStore(client(), { keyPrefix: ns('a') });
    await store.save('c1', { clientId: 'app', scope: ['read'] }, 5_000);

    assert.equal((await store.consume('c1')).clientId, 'app');
    assert.equal(await store.consume('c1'), undefined, 'a code must not be redeemable twice');
  });

  test('an authorization code carries its expiry into Redis', async () => {
    const keyPrefix = ns('b');
    const store = createRedisAuthCodeStore(client(), { keyPrefix });
    await store.save('c-ttl', { clientId: 'app' }, 60_000);

    const pttl = await raw.pttl(`${keyPrefix}code:c-ttl`);
    assert.ok(
      pttl > 0 && pttl <= 60_000,
      `an authorization code must expire on its own; got PTTL ${pttl} (-1 means it never expires)`,
    );
  });

  test('refresh rotate + revokeFamily', async () => {
    const store = createRedisRefreshStore(client(), { keyPrefix: ns('c') });
    const base = { familyId: 'f1', clientId: 'app', scope: [], expiresAt: Date.now() + 5_000 };

    await store.save({ ...base, token: 't1' });
    await store.rotate('t1', { ...base, token: 't2' });
    assert.equal((await store.get('t1')).used, true);

    await store.revokeFamily('f1');
    assert.equal((await store.get('t2')).revoked, true);
  });

  test('an expired refresh record reads as absent', async () => {
    const store = createRedisRefreshStore(client(), { keyPrefix: ns('d') });
    await store.save({ token: 't1', familyId: 'f1', clientId: 'app', scope: [], expiresAt: Date.now() - 1 });
    assert.equal(await store.get('t1'), null);
  });

  test('device lookup + reverse-index cleanup', async () => {
    const store = createRedisDeviceStore(client(), { keyPrefix: ns('e') });
    await store.save({ deviceCode: 'd1', userCode: 'WXYZ-2345', clientId: 'app', scope: [], status: 'pending' }, 5_000);

    assert.equal((await store.getByUserCode('WXYZ-2345')).deviceCode, 'd1');
    await store.update('d1', { status: 'redeemed' });
    assert.equal(await store.getByUserCode('WXYZ-2345'), undefined);
  });
});
