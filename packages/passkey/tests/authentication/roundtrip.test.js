import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { begin as regBegin, finish as regFinish } from '../../src/registration/index.js';
import { begin as authBegin, finish as authFinish } from '../../src/authentication/index.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';
import { makeNoneResponse, makeAssertionResponse } from '../_helpers/webauthnFixture.js';

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';
const SECRET = 'a'.repeat(64);

function memoryIncrStore() {
  const map = new Map();
  return {
    async incr(key, ttlMs) {
      const now = Date.now();
      const entry = map.get(key);
      if (!entry || entry.expiresAt <= now) {
        const fresh = { count: 1, expiresAt: now + ttlMs };
        map.set(key, fresh);
        return { count: 1, expiresAt: fresh.expiresAt };
      }
      entry.count += 1;
      return { count: entry.count, expiresAt: entry.expiresAt };
    },
    async get(key) {
      return map.get(key) ?? null;
    },
    async delete(key) {
      map.delete(key);
    },
  };
}

async function register(store) {
  const beginRes = await regBegin({
    rp: { id: RP_ID, name: 'Example' },
    user: { id: 'u_1', name: 'alice', displayName: 'Alice' },
    challengeSecret: SECRET,
    challengeStore: store,
  });
  const fixture = makeNoneResponse({
    rpId: RP_ID,
    challengeBase64Url: beginRes.options.challenge,
    origin: ORIGIN,
  });
  const finishRes = await regFinish({
    response: fixture.response,
    challengeToken: beginRes.challengeToken,
    expectedRpId: RP_ID,
    expectedOrigin: ORIGIN,
    challengeSecret: SECRET,
    challengeStore: store,
    expectedUserId: 'u_1',
  });
  return { credential: finishRes.credential, privateKey: fixture.privateKey };
}

describe('authentication.begin', () => {
  test('returns options + challengeToken with rpId echoed', async () => {
    const store = memoryIncrStore();
    const out = await authBegin({
      rpId: RP_ID,
      challengeSecret: SECRET,
      challengeStore: store,
    });
    assert.equal(out.options.rpId, RP_ID);
    assert.equal(typeof out.options.challenge, 'string');
    assert.equal(typeof out.challengeToken, 'string');
  });

  test('conditional mediation surfaces on options', async () => {
    const store = memoryIncrStore();
    const out = await authBegin({
      rpId: RP_ID,
      challengeSecret: SECRET,
      challengeStore: store,
      conditional: true,
    });
    assert.equal(out.options.mediation, 'conditional');
  });

  test('array rpId — first is primary in options', async () => {
    const store = memoryIncrStore();
    const out = await authBegin({
      rpId: [RP_ID, 'example.co.uk'],
      challengeSecret: SECRET,
      challengeStore: store,
    });
    assert.equal(out.options.rpId, RP_ID);
  });
});

describe('authentication.finish', () => {
  test('happy path round-trip', async () => {
    const store = memoryIncrStore();
    const { credential, privateKey } = await register(store);

    const beginRes = await authBegin({ rpId: RP_ID, challengeSecret: SECRET, challengeStore: store });
    const assertion = makeAssertionResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
      privateKey,
      counter: 5,
      credentialId: credential.idBytes,
    });

    const res = await authFinish({
      response: assertion,
      challengeToken: beginRes.challengeToken,
      expectedRpId: RP_ID,
      expectedOrigin: ORIGIN,
      challengeSecret: SECRET,
      challengeStore: store,
      credential,
    });

    assert.equal(res.verified, true);
    assert.equal(res.newCounter, 5);
    assert.equal(res.rpId, RP_ID);
  });

  test('rejects counter rollback', async () => {
    const store = memoryIncrStore();
    const { credential, privateKey } = await register(store);
    credential.counter = 10; // pretend we've seen a higher counter already

    const beginRes = await authBegin({ rpId: RP_ID, challengeSecret: SECRET, challengeStore: store });
    const assertion = makeAssertionResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
      privateKey,
      counter: 5, // rewind
      credentialId: credential.idBytes,
    });

    await assert.rejects(
      () =>
        authFinish({
          response: assertion,
          challengeToken: beginRes.challengeToken,
          expectedRpId: RP_ID,
          expectedOrigin: ORIGIN,
          challengeSecret: SECRET,
          challengeStore: store,
          credential,
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.COUNTER_ROLLBACK,
    );
  });

  test('allows counter=0 with stored=0 (no-counter authenticators)', async () => {
    const store = memoryIncrStore();
    const { credential, privateKey } = await register(store);
    credential.counter = 0;

    const beginRes = await authBegin({ rpId: RP_ID, challengeSecret: SECRET, challengeStore: store });
    const assertion = makeAssertionResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
      privateKey,
      counter: 0,
      credentialId: credential.idBytes,
    });

    const res = await authFinish({
      response: assertion,
      challengeToken: beginRes.challengeToken,
      expectedRpId: RP_ID,
      expectedOrigin: ORIGIN,
      challengeSecret: SECRET,
      challengeStore: store,
      credential,
    });
    assert.equal(res.newCounter, 0);
  });

  test('rejects tampered signature', async () => {
    const store = memoryIncrStore();
    const { credential, privateKey } = await register(store);

    const beginRes = await authBegin({ rpId: RP_ID, challengeSecret: SECRET, challengeStore: store });
    const assertion = makeAssertionResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
      privateKey,
      counter: 5,
      credentialId: credential.idBytes,
    });
    // Flip a byte in signature.
    const sigBytes = Buffer.from(assertion.response.signature, 'base64url');
    sigBytes[5] ^= 0xff;
    assertion.response.signature = sigBytes.toString('base64url');

    await assert.rejects(
      () =>
        authFinish({
          response: assertion,
          challengeToken: beginRes.challengeToken,
          expectedRpId: RP_ID,
          expectedOrigin: ORIGIN,
          challengeSecret: SECRET,
          challengeStore: store,
          credential,
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.SIGNATURE_INVALID,
    );
  });

  test('crossOrigin=true rejected by default → CLIENT_DATA_INVALID', async () => {
    const store = memoryIncrStore();
    const { credential, privateKey } = await register(store);

    const beginRes = await authBegin({ rpId: RP_ID, challengeSecret: SECRET, challengeStore: store });
    const assertion = makeAssertionResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
      privateKey,
      counter: 5,
      credentialId: credential.idBytes,
      crossOrigin: true,
    });

    await assert.rejects(
      () =>
        authFinish({
          response: assertion,
          challengeToken: beginRes.challengeToken,
          expectedRpId: RP_ID,
          expectedOrigin: ORIGIN,
          challengeSecret: SECRET,
          challengeStore: store,
          credential,
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.CLIENT_DATA_INVALID,
    );
  });

  test('requireBackupEligible rejects a non-syncable assertion', async () => {
    const store = memoryIncrStore();
    const { credential, privateKey } = await register(store);

    const beginRes = await authBegin({ rpId: RP_ID, challengeSecret: SECRET, challengeStore: store });
    const assertion = makeAssertionResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
      privateKey,
      counter: 5,
      credentialId: credential.idBytes,
      flags: 0x05, // UP + UV, BE=0
    });

    await assert.rejects(
      () =>
        authFinish({
          response: assertion,
          challengeToken: beginRes.challengeToken,
          expectedRpId: RP_ID,
          expectedOrigin: ORIGIN,
          challengeSecret: SECRET,
          challengeStore: store,
          credential,
          requireBackupEligible: true,
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.BACKUP_ELIGIBLE_REQUIRED,
    );
  });
});
