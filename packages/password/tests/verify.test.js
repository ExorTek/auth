import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as scrypt from '../src/algorithms/scrypt.js';
import * as pbkdf2 from '../src/algorithms/pbkdf2.js';
import * as argon2 from '../src/algorithms/argon2.js';
import * as bcrypt from '../src/algorithms/bcrypt.js';
import { verify, needsRehash, identifyAlgorithm } from '../src/verify.js';

let argon2Available = false;
let bcryptAvailable = false;
try {
  await import('argon2');
  argon2Available = true;
} catch {
  /* skip */
}
try {
  await import('bcryptjs');
  bcryptAvailable = true;
} catch {
  /* skip */
}

test('verify: routes scrypt hash to scrypt.verify', async () => {
  const s = await scrypt.hash('pw', { N: 1 << 12 });
  assert.equal(await verify('pw', s), true);
  assert.equal(await verify('wrong', s), false);
});

test('verify: routes pbkdf2 hash', async () => {
  const s = await pbkdf2.hash('pw', { iterations: 1000 });
  assert.equal(await verify('pw', s), true);
  assert.equal(await verify('wrong', s), false);
});

test('verify: routes argon2', { skip: !argon2Available && 'argon2 peer not installed' }, async () => {
  const s = await argon2.hash('pw', { memoryCost: 8, timeCost: 1, parallelism: 1 });
  assert.equal(await verify('pw', s), true);
});

test('verify: routes bcrypt', { skip: !bcryptAvailable && 'bcryptjs peer not installed' }, async () => {
  const s = await bcrypt.hash('pw', { rounds: 4 });
  assert.equal(await verify('pw', s), true);
});

test('verify: unrecognised hash → false', async () => {
  assert.equal(await verify('anything', 'plain-text'), false);
  assert.equal(await verify('anything', '$notreal$'), false);
  assert.equal(await verify('anything', ''), false);
});

test('identifyAlgorithm: correctly labels each format', async () => {
  const s = await scrypt.hash('pw', { N: 1 << 12 });
  assert.equal(identifyAlgorithm(s), 'scrypt');
  const p = await pbkdf2.hash('pw', { iterations: 1000 });
  assert.equal(identifyAlgorithm(p), 'pbkdf2-sha256');
  assert.equal(identifyAlgorithm('not-a-hash'), null);
});

test('needsRehash: target=scrypt, stored pbkdf2 → true', async () => {
  const p = await pbkdf2.hash('pw', { iterations: 1000 });
  assert.equal(needsRehash(p, { target: 'scrypt' }), true);
});

test('needsRehash: target=scrypt, stored current scrypt → false', async () => {
  const s = await scrypt.hash('pw');
  assert.equal(needsRehash(s, { target: 'scrypt' }), false);
});

test('needsRehash: unknown target rejected', async () => {
  const s = await scrypt.hash('pw', { N: 1 << 12 });
  assert.throws(() => needsRehash(s, { target: 'md5' }));
});

// constantTimeVerify

import { constantTimeVerify } from '../src/verify.js';

test('constantTimeVerify: with a real hash → same as verify', async () => {
  const s = await scrypt.hash('correct', { N: 1 << 12 });
  assert.equal(await constantTimeVerify('correct', s), true);
  assert.equal(await constantTimeVerify('wrong', s), false);
});

test('constantTimeVerify: missing storedHash → always false, still runs a real verify', async () => {
  // We can't easily assert exact timing, but we can assert the function
  // returns false consistently regardless of input and doesn't short-circuit.
  const t0 = performance.now();
  const r = await constantTimeVerify('anything', null);
  const dt = performance.now() - t0;
  assert.equal(r, false);
  // Decoy hash uses scrypt with owasp2024 defaults (N=2^17). Even on a
  // fast box that's ≥ 10ms. A short-circuit would be < 1ms.
  assert.ok(dt >= 5, `expected constantTimeVerify to spend real time on a missing hash; measured ${dt}ms`);
});

test('constantTimeVerify: undefined / empty string also triggers decoy path', async () => {
  assert.equal(await constantTimeVerify('anything', undefined), false);
  assert.equal(await constantTimeVerify('anything', ''), false);
});
