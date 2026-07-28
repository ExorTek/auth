import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { begin } from '../../src/registration/begin.js';
import { finish } from '../../src/registration/finish.js';
import { PasskeyError, ErrorCode } from '../../src/errors.js';
import { makeNoneResponse, makePackedSelfResponse } from '../_helpers/webauthnFixture.js';

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

describe('registration.begin', () => {
  test('returns options + challengeToken', async () => {
    const store = memoryIncrStore();
    const out = await begin({
      rp: { id: RP_ID, name: 'Example' },
      user: { id: 'u_1', name: 'alice', displayName: 'Alice' },
      challengeSecret: SECRET,
      challengeStore: store,
    });
    assert.equal(out.options.rp.id, RP_ID);
    assert.equal(typeof out.options.challenge, 'string');
    assert.ok(out.options.pubKeyCredParams.length > 0);
    assert.ok(out.options.pubKeyCredParams.every(p => p.type === 'public-key'));
    assert.equal(typeof out.challengeToken, 'string');
  });

  test('rejects attestation=indirect (v13 spec-cleanup)', async () => {
    await assert.rejects(
      () =>
        begin({
          rp: { id: RP_ID, name: 'Example' },
          user: { id: 'u_1', name: 'a', displayName: 'A' },
          challengeSecret: SECRET,
          challengeStore: memoryIncrStore(),
          attestation: 'indirect',
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });

  test('validates hint values', async () => {
    await assert.rejects(
      () =>
        begin({
          rp: { id: RP_ID, name: 'Example' },
          user: { id: 'u_1', name: 'a', displayName: 'A' },
          challengeSecret: SECRET,
          challengeStore: memoryIncrStore(),
          hints: ['nope'],
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.INVALID_ARGUMENT,
    );
  });
});

describe('registration.finish — fmt "none"', () => {
  test('happy path round-trip', async () => {
    const store = memoryIncrStore();
    const beginRes = await begin({
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
    const res = await finish({
      response: fixture.response,
      challengeToken: beginRes.challengeToken,
      expectedRpId: RP_ID,
      expectedOrigin: ORIGIN,
      challengeSecret: SECRET,
      challengeStore: store,
      expectedUserId: 'u_1',
    });
    assert.equal(res.attestation.format, 'none');
    assert.equal(res.credential.algorithm, -7);
    assert.equal(res.rpId, RP_ID);
    assert.equal(res.aaguid, '00112233-4455-6677-8899-aabbccddeeff');
    assert.equal(res.deviceType, 'singleDevice');
  });

  test('rejects a wrong-origin response', async () => {
    const store = memoryIncrStore();
    const beginRes = await begin({
      rp: { id: RP_ID, name: 'Example' },
      user: { id: 'u_1', name: 'a', displayName: 'A' },
      challengeSecret: SECRET,
      challengeStore: store,
    });
    const fixture = makeNoneResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: 'https://evil.com',
    });
    await assert.rejects(
      () =>
        finish({
          response: fixture.response,
          challengeToken: beginRes.challengeToken,
          expectedRpId: RP_ID,
          expectedOrigin: ORIGIN,
          challengeSecret: SECRET,
          challengeStore: store,
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.ORIGIN_MISMATCH,
    );
  });

  test('rejects wrong RP ID hash', async () => {
    const store = memoryIncrStore();
    const beginRes = await begin({
      rp: { id: RP_ID, name: 'Example' },
      user: { id: 'u_1', name: 'a', displayName: 'A' },
      challengeSecret: SECRET,
      challengeStore: store,
    });
    const fixture = makeNoneResponse({
      rpId: 'other.com',
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
    });
    await assert.rejects(
      () =>
        finish({
          response: fixture.response,
          challengeToken: beginRes.challengeToken,
          expectedRpId: RP_ID,
          expectedOrigin: ORIGIN,
          challengeSecret: SECRET,
          challengeStore: store,
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.RP_ID_MISMATCH,
    );
  });

  test('rejects replayed challengeToken', async () => {
    const store = memoryIncrStore();
    const beginRes = await begin({
      rp: { id: RP_ID, name: 'Example' },
      user: { id: 'u_1', name: 'a', displayName: 'A' },
      challengeSecret: SECRET,
      challengeStore: store,
    });
    const fixture = makeNoneResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
    });
    await finish({
      response: fixture.response,
      challengeToken: beginRes.challengeToken,
      expectedRpId: RP_ID,
      expectedOrigin: ORIGIN,
      challengeSecret: SECRET,
      challengeStore: store,
      expectedUserId: 'u_1',
    });
    // Second finish() with the same challenge token must reject.
    await assert.rejects(
      () =>
        finish({
          response: fixture.response,
          challengeToken: beginRes.challengeToken,
          expectedRpId: RP_ID,
          expectedOrigin: ORIGIN,
          challengeSecret: SECRET,
          challengeStore: store,
          expectedUserId: 'u_1',
        }),
      err => err instanceof PasskeyError && err.code === ErrorCode.CHALLENGE_ALREADY_USED,
    );
  });
});

describe('registration.finish — fmt "packed" (self attestation)', () => {
  test('happy path round-trip', async () => {
    const store = memoryIncrStore();
    const beginRes = await begin({
      rp: { id: RP_ID, name: 'Example' },
      user: { id: 'u_1', name: 'alice', displayName: 'Alice' },
      challengeSecret: SECRET,
      challengeStore: store,
    });
    const fixture = makePackedSelfResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
    });
    const res = await finish({
      response: fixture.response,
      challengeToken: beginRes.challengeToken,
      expectedRpId: RP_ID,
      expectedOrigin: ORIGIN,
      challengeSecret: SECRET,
      challengeStore: store,
      expectedUserId: 'u_1',
    });
    assert.equal(res.attestation.format, 'packed');
    assert.equal(res.attestation.trustPath, 'self');
  });

  test('rejects packed self attestation with wrong signature', async () => {
    const store = memoryIncrStore();
    const beginRes = await begin({
      rp: { id: RP_ID, name: 'Example' },
      user: { id: 'u_1', name: 'a', displayName: 'A' },
      challengeSecret: SECRET,
      challengeStore: store,
    });
    const fixture = makePackedSelfResponse({
      rpId: RP_ID,
      challengeBase64Url: beginRes.options.challenge,
      origin: ORIGIN,
    });
    // Corrupt the attestationObject bytes.
    const bytes = Buffer.from(fixture.response.response.attestationObject, 'base64url');
    bytes[bytes.length - 5] ^= 0xff;
    fixture.response.response.attestationObject = bytes.toString('base64url');

    await assert.rejects(
      () =>
        finish({
          response: fixture.response,
          challengeToken: beginRes.challengeToken,
          expectedRpId: RP_ID,
          expectedOrigin: ORIGIN,
          challengeSecret: SECRET,
          challengeStore: store,
        }),
      err => err instanceof PasskeyError,
    );
  });
});
