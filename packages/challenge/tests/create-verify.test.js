import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { ChallengeError, ErrorCode, createChallenge, verifyChallenge } from '../src/index.js';
import { memoryStore } from '../src/stores/memory.js';

const SECRET = randomBytes(32);

test('round-trip: create → verify returns { valid: true, payload }', async () => {
  const token = await createChallenge({
    secret: SECRET,
    userId: 'usr_1',
    method: 'totp',
    step: 'mfa_verified',
    nextStep: 'login',
    expiresIn: '5m',
  });
  assert.match(token, /^chall_v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  const res = await verifyChallenge(token, { secret: SECRET });
  assert.equal(res.valid, true);
  assert.equal(res.payload.userId, 'usr_1');
  assert.equal(res.payload.method, 'totp');
  assert.equal(res.payload.step, 'mfa_verified');
  assert.equal(res.payload.nextStep, 'login');
});

test('verify: bad_signature when tag is tampered with', async () => {
  const token = await createChallenge({ secret: SECRET, expiresIn: '5m' });
  const [prefix, payload] = token.split('.');
  const tampered = `${prefix}.${payload}.AAAAAAAA`;
  const res = await verifyChallenge(tampered, { secret: SECRET });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'bad_signature');
});

test('verify: malformed on totally bogus input', async () => {
  for (const input of ['', 'not-a-token', 'chall_v0.a.b', 'chall_v1.only-two']) {
    const res = await verifyChallenge(input, { secret: SECRET });
    assert.equal(res.valid, false);
    assert.equal(res.reason, 'malformed', `input: ${input}`);
  }
});

test('verify: wrong secret → bad_signature', async () => {
  const token = await createChallenge({ secret: SECRET, expiresIn: '5m' });
  const res = await verifyChallenge(token, { secret: randomBytes(32) });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'bad_signature');
});

test('verify: expired token → expired', async () => {
  const token = await createChallenge({ secret: SECRET, expiresIn: '5m', now: 1_000_000 });
  // Fast-forward past the exp.
  const res = await verifyChallenge(token, { secret: SECRET, now: 1_000_000 + 6 * 60_000 });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'expired');
});

test('verify: future iat outside tolerance → not_yet_valid', async () => {
  const token = await createChallenge({ secret: SECRET, expiresIn: '5m', now: 10_000_000 });
  // Verifier clock 5 minutes BEHIND issuer — well outside the 60s tolerance.
  const res = await verifyChallenge(token, { secret: SECRET, now: 10_000_000 - 5 * 60_000 });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'not_yet_valid');
});

test('verify: expected* mismatches yield the matching reason', async () => {
  const token = await createChallenge({
    secret: SECRET,
    userId: 'u1',
    method: 'totp',
    step: 's1',
    nextStep: 'n1',
    expiresIn: '5m',
  });
  const cases = [
    { opt: { expectedUserId: 'u2' }, reason: 'user_mismatch' },
    { opt: { expectedMethod: 'sms_otp' }, reason: 'method_mismatch' },
    { opt: { expectedStep: 's2' }, reason: 'step_mismatch' },
    { opt: { expectedNextStep: 'n2' }, reason: 'next_step_mismatch' },
  ];
  for (const { opt, reason } of cases) {
    const res = await verifyChallenge(token, { secret: SECRET, ...opt });
    assert.equal(res.valid, false);
    assert.equal(res.reason, reason);
  }
});

test('ipBinding: verify with matching ip passes, wrong ip fails', async () => {
  const token = await createChallenge({
    secret: SECRET,
    expiresIn: '5m',
    ipBinding: true,
    ip: '1.2.3.4',
  });
  const ok = await verifyChallenge(token, { secret: SECRET, ip: '1.2.3.4' });
  assert.equal(ok.valid, true);
  assert.equal(ok.payload.ip, '1.2.3.4');
  const bad = await verifyChallenge(token, { secret: SECRET, ip: '5.6.7.8' });
  assert.equal(bad.valid, false);
  assert.equal(bad.reason, 'ip_mismatch');
  const missing = await verifyChallenge(token, { secret: SECRET });
  assert.equal(missing.valid, false);
  assert.equal(missing.reason, 'ip_missing');
});

test('singleUse: consume enforces one-shot; second verify → replay', async () => {
  const store = memoryStore();
  try {
    const token = await createChallenge({
      secret: SECRET,
      expiresIn: '5m',
      singleUse: true,
      store,
    });
    const first = await verifyChallenge(token, { secret: SECRET, consume: true, store });
    assert.equal(first.valid, true);
    // Internal `su` marker stripped from payload.
    assert.equal('su' in first.payload, false);
    const second = await verifyChallenge(token, { secret: SECRET, consume: true, store });
    assert.equal(second.valid, false);
    assert.equal(second.reason, 'replay');
  } finally {
    store._stop();
  }
});

test('singleUse: without consume, verify does NOT touch the store', async () => {
  const store = memoryStore();
  try {
    const token = await createChallenge({
      secret: SECRET,
      expiresIn: '5m',
      singleUse: true,
      store,
    });
    const a = await verifyChallenge(token, { secret: SECRET });
    const b = await verifyChallenge(token, { secret: SECRET });
    assert.equal(a.valid, true);
    assert.equal(b.valid, true);
    assert.equal(store._size(), 0);
  } finally {
    store._stop();
  }
});

test('singleUse without store at create time → throws INVALID_ARGUMENT', async () => {
  await assert.rejects(
    createChallenge({ secret: SECRET, expiresIn: '5m', singleUse: true }),
    err => err instanceof ChallengeError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('verify with consume: true but no store → throws INVALID_ARGUMENT', async () => {
  const token = await createChallenge({ secret: SECRET, expiresIn: '5m' });
  await assert.rejects(
    verifyChallenge(token, { secret: SECRET, consume: true }),
    err => err instanceof ChallengeError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('secret shorter than 32 bytes → INVALID_SECRET', async () => {
  await assert.rejects(
    createChallenge({ secret: 'too-short', expiresIn: '5m' }),
    err => err instanceof ChallengeError && err.code === ErrorCode.INVALID_SECRET,
  );
});

test('accepts secret as UTF-8 string, Buffer, or Uint8Array', async () => {
  const s1 = 'x'.repeat(32);
  const s2 = Buffer.from(s1);
  const s3 = new Uint8Array(s2);
  for (const secret of [s1, s2, s3]) {
    const token = await createChallenge({ secret, expiresIn: '5m' });
    const res = await verifyChallenge(token, { secret });
    assert.equal(res.valid, true);
  }
});

test('expiresIn: rejects non-positive / non-finite', async () => {
  for (const bad of [0, -1, NaN, Infinity, '0ms']) {
    await assert.rejects(
      createChallenge({ secret: SECRET, expiresIn: bad }),
      err => err instanceof ChallengeError && err.code === ErrorCode.INVALID_ARGUMENT,
      `expiresIn=${bad}`,
    );
  }
});

test('metadata: attached and returned on verify', async () => {
  const token = await createChallenge({
    secret: SECRET,
    expiresIn: '5m',
    metadata: { redirectTo: '/dashboard', flag: true },
  });
  const res = await verifyChallenge(token, { secret: SECRET });
  assert.equal(res.valid, true);
  assert.deepEqual(res.payload.meta, { redirectTo: '/dashboard', flag: true });
});

test('custom prefix: create with prefix A, verify with same prefix', async () => {
  const token = await createChallenge({
    secret: SECRET,
    expiresIn: '5m',
    prefix: 'server_challenge',
    userId: 'u1',
  });
  assert.ok(token.startsWith('server_challenge.'));
  const res = await verifyChallenge(token, { secret: SECRET, prefix: 'server_challenge' });
  assert.equal(res.valid, true);
  assert.equal(res.payload.userId, 'u1');
});

test('custom prefix: mismatch → malformed (not bad_signature)', async () => {
  const token = await createChallenge({ secret: SECRET, expiresIn: '5m', prefix: 'myapp_v1' });
  const res = await verifyChallenge(token, { secret: SECRET });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'malformed');
});

test('prefix validation: rejects illegal chars / length / shape', async () => {
  for (const bad of ['', 'has.dot', 'has space', 'x'.repeat(33), 42, null]) {
    await assert.rejects(
      createChallenge({ secret: SECRET, expiresIn: '5m', prefix: bad }),
      err => err instanceof ChallengeError && err.code === ErrorCode.INVALID_ARGUMENT,
      `prefix=${JSON.stringify(bad)}`,
    );
  }
});

test('store failure inside verify → store_unavailable', async () => {
  const brokenStore = {
    async incr() {
      throw new Error('redis down');
    },
  };
  const token = await createChallenge({
    secret: SECRET,
    expiresIn: '5m',
    singleUse: true,
    store: brokenStore,
  });
  const res = await verifyChallenge(token, { secret: SECRET, consume: true, store: brokenStore });
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'store_unavailable');
});
