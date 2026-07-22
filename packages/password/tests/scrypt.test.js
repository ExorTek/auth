import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as scrypt from '../src/algorithms/scrypt.js';

// Use a low-N variant across tests to stay quick — real deployments run
// the 2^17 default, but 2^12 is plenty for correctness assertions.
const FAST = { N: 1 << 12 };

test('scrypt.hash returns a PHC string with the expected shape', async () => {
  const s = await scrypt.hash('correct horse battery staple', FAST);
  assert.match(s, /^\$scrypt\$ln=12,r=8,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);
});

test('scrypt.verify: right password → true, wrong → false', async () => {
  const s = await scrypt.hash('correct horse', FAST);
  assert.equal(await scrypt.verify('correct horse', s), true);
  assert.equal(await scrypt.verify('wrong horse', s), false);
});

test('scrypt.verify: NFKC normalization survives round-trip', async () => {
  const s = await scrypt.hash('café', FAST);
  // Decomposed 'e' + combining acute
  assert.equal(await scrypt.verify('café', s), true);
});

test('scrypt.verify returns false for wrong-algo hash', async () => {
  assert.equal(
    await scrypt.verify(
      'anything',
      '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA',
    ),
    false,
  );
});

test('scrypt.verify returns false for malformed hash', async () => {
  assert.equal(await scrypt.verify('anything', 'not-a-hash'), false);
  assert.equal(await scrypt.verify('anything', ''), false);
});

test('scrypt.hash uses a fresh salt per call', async () => {
  const a = await scrypt.hash('same', FAST);
  const b = await scrypt.hash('same', FAST);
  assert.notEqual(a, b);
});

test('scrypt.needsRehash: same params as default → false', async () => {
  const s = await scrypt.hash('pw', { N: scrypt.scryptDefaults.N });
  assert.equal(scrypt.needsRehash(s), false);
});

test('scrypt.needsRehash: weaker params → true', async () => {
  const s = await scrypt.hash('pw', FAST);
  assert.equal(scrypt.needsRehash(s), true);
});

test('scrypt.needsRehash: unrecognised hash → true', () => {
  assert.equal(scrypt.needsRehash('$notreal$'), true);
  assert.equal(scrypt.needsRehash(''), true);
});

test('scrypt: rejects non-power-of-two N', async () => {
  await assert.rejects(scrypt.hash('pw', { N: 100 }));
});

test('scrypt: rejects negative / zero params', async () => {
  await assert.rejects(scrypt.hash('pw', { ...FAST, r: 0 }));
  await assert.rejects(scrypt.hash('pw', { ...FAST, keyLength: -1 }));
});

test('scrypt.verify: rejects poisoned ln beyond hash-side ceiling (DoS)', async () => {
  // hash-side `assertN` caps at 1<<24 (ln=24). A poisoned stored value
  // claiming ln=31 would otherwise trigger a multi-terabyte allocation.
  const poisoned = '$scrypt$ln=31,r=8,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA';
  const t0 = Date.now();
  const ok = await scrypt.verify('pw', poisoned);
  const elapsed = Date.now() - t0;
  assert.equal(ok, false);
  assert.ok(elapsed < 100, `poisoned verify should short-circuit, took ${elapsed}ms`);
});

test('scrypt.verify: rejects poisoned r / p beyond sane ceiling (DoS)', async () => {
  // 128 × N × r is the scrypt working set — r has to be capped too.
  const poisonedR = '$scrypt$ln=15,r=99,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA';
  const poisonedP = '$scrypt$ln=15,r=8,p=99$c2FsdHNhbHRzYWx0c2E$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA';
  assert.equal(await scrypt.verify('pw', poisonedR), false);
  assert.equal(await scrypt.verify('pw', poisonedP), false);
});
