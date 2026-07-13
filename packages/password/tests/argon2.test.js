import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as argon2 from '../src/algorithms/argon2.js';

let available = false;
try {
  await import('argon2');
  available = true;
} catch {
  /* peer not installed — skip the roundtrip tests below */
}

// Fast params: minimum memory + time for correctness-only tests. Real
// hashes use 19 MiB × 2 iterations.
const FAST = { memoryCost: 8, timeCost: 1, parallelism: 1 };

test('argon2.hash returns argon2id PHC by default', { skip: !available && 'argon2 peer not installed' }, async () => {
  const s = await argon2.hash('pw', FAST);
  assert.match(s, /^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$/);
});

test('argon2.verify round-trip', { skip: !available && 'argon2 peer not installed' }, async () => {
  const s = await argon2.hash('correct horse', FAST);
  assert.equal(await argon2.verify('correct horse', s), true);
  assert.equal(await argon2.verify('wrong horse', s), false);
});

test('argon2.verify: wrong-algo hash → false', { skip: !available && 'argon2 peer not installed' }, async () => {
  assert.equal(await argon2.verify('anything', '$scrypt$ln=17,r=8,p=1$c2FsdA$aGFzaA'), false);
  assert.equal(await argon2.verify('anything', 'not-a-hash'), false);
});

test('argon2.needsRehash: unrecognised hash → true', () => {
  assert.equal(argon2.needsRehash(''), true);
  assert.equal(argon2.needsRehash('$scrypt$ln=17,r=8,p=1$c2FsdA$aGFzaA'), true);
});

test('argon2.needsRehash: variant mismatch → true', { skip: !available && 'argon2 peer not installed' }, async () => {
  const s = await argon2.hash('pw', { ...FAST, type: 'argon2i' });
  assert.equal(argon2.needsRehash(s, { type: 'argon2id' }), true);
});

test(
  'argon2.needsRehash: weaker cost than target → true',
  { skip: !available && 'argon2 peer not installed' },
  async () => {
    const s = await argon2.hash('pw', { memoryCost: 8, timeCost: 1, parallelism: 1 });
    assert.equal(argon2.needsRehash(s, { memoryCost: 19_456, timeCost: 2, parallelism: 1 }), true);
  },
);

test('argon2.hash: unknown type rejected', async () => {
  await assert.rejects(argon2.hash('pw', { type: 'argon2xyz' }));
});
