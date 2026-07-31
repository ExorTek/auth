/**
 * Token-pair layer: create / rotate / reuse-detection / revoke over the
 * in-memory store, for both access purposes.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { create, rotate, revoke, revokeAll, tokenPair } from '../src/token-pair.js';
import { createStore } from '../src/stores.js';
import { decrypt, verify, generateKey, generateKeyPair, PasetoError, ErrorCode } from '../src/index.js';

const localSecret = () => ({ access: generateKey() });

test('namespace exposes create/rotate/revoke/revokeAll', () => {
  for (const fn of [tokenPair.create, tokenPair.rotate, tokenPair.revoke, tokenPair.revokeAll]) {
    assert.equal(typeof fn, 'function');
  }
  assert.ok(Object.isFrozen(tokenPair));
});

test('create issues a v4.local access token (default purpose) + opaque refresh', async () => {
  const store = createStore('memory');
  const secret = localSecret();
  const res = await create(
    { userId: 1 },
    { secret, access: { expiresIn: '15m' }, refresh: { expiresIn: '7d', store } },
  );
  assert.ok(res.accessToken.startsWith('v4.local.'));
  assert.ok(!res.refreshToken.includes('.'), 'opaque refresh is a bare random string');
  assert.equal(decrypt(res.accessToken, secret.access).userId, 1);
  assert.ok(res.accessExpiresAt instanceof Date);
  assert.ok(typeof res.familyId === 'string');
  store._stop();
});

test('access purpose:public issues a verifiable v4.public token', async () => {
  const store = createStore('memory');
  const { secretKey, publicKey } = generateKeyPair();
  const res = await create(
    { userId: 2 },
    {
      secret: { access: secretKey },
      access: { purpose: 'public', expiresIn: '15m' },
      refresh: { expiresIn: '7d', store },
    },
  );
  assert.ok(res.accessToken.startsWith('v4.public.'));
  assert.equal(verify(res.accessToken, publicKey).userId, 2);
  store._stop();
});

test('rotate issues a fresh pair and consumes the old refresh', async () => {
  const store = createStore('memory');
  const secret = localSecret();
  const opts = { secret, access: { expiresIn: '15m' }, refresh: { expiresIn: '7d', store } };
  const first = await create({ userId: 1 }, opts);
  const second = await rotate(first.refreshToken, opts);
  assert.notEqual(second.refreshToken, first.refreshToken);
  assert.equal(second.familyId, first.familyId, 'family is preserved across rotation');
  assert.equal(decrypt(second.accessToken, secret.access).userId, 1);
  store._stop();
});

test('reusing a rotated refresh token revokes the whole family (REFRESH_REUSED)', async () => {
  const store = createStore('memory');
  const secret = localSecret();
  const opts = { secret, access: { expiresIn: '15m' }, refresh: { expiresIn: '7d', store } };
  const first = await create({ userId: 1 }, opts);
  await rotate(first.refreshToken, opts);

  await assert.rejects(
    () => rotate(first.refreshToken, opts),
    err => err instanceof PasetoError && err.code === ErrorCode.REFRESH_REUSED,
  );
  store._stop();
});

test('an unknown refresh token is rejected with REVOKED', async () => {
  const store = createStore('memory');
  const opts = { secret: localSecret(), access: { expiresIn: '15m' }, refresh: { expiresIn: '7d', store } };
  await assert.rejects(
    () => rotate('never-issued', opts),
    err => err instanceof PasetoError && err.code === ErrorCode.REVOKED,
  );
  store._stop();
});

test('revoke removes a single refresh; revokeAll clears a family', async () => {
  const store = createStore('memory');
  const secret = localSecret();
  const opts = { secret, access: { expiresIn: '15m' }, refresh: { expiresIn: '7d', store } };

  const a = await create({ userId: 1 }, opts);
  await revoke(a.refreshToken, { store });
  await assert.rejects(
    () => rotate(a.refreshToken, opts),
    err => err.code === ErrorCode.REVOKED,
  );

  const b = await create({ userId: 2 }, opts);
  const count = await revokeAll(b.familyId, { store });
  assert.ok(count >= 1);
  await assert.rejects(
    () => rotate(b.refreshToken, opts),
    err => err.code === ErrorCode.REVOKED,
  );
  store._stop();
});

test('opaque:false mints a PASETO refresh token', async () => {
  const store = createStore('memory');
  const secret = { access: generateKey(), refresh: generateKey() };
  const res = await create(
    { userId: 9 },
    { secret, access: { expiresIn: '15m' }, refresh: { expiresIn: '7d', opaque: false, store } },
  );
  assert.ok(res.refreshToken.startsWith('v4.local.'));
  assert.equal(decrypt(res.refreshToken, secret.refresh).kind, 'refresh');
  store._stop();
});

test('missing required options throw INVALID_ARGUMENT', async () => {
  const store = createStore('memory');
  await assert.rejects(
    () => create({}, { secret: localSecret(), access: {}, refresh: { expiresIn: '7d', store } }),
    err => err instanceof PasetoError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
  store._stop();
});
