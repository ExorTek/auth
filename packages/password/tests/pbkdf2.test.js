import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as pbkdf2 from '../src/algorithms/pbkdf2.js';

const FAST = { iterations: 1000 };

test('pbkdf2.hash returns PHC with sha256 default', async () => {
  const s = await pbkdf2.hash('pw', FAST);
  assert.match(s, /^\$pbkdf2-sha256\$i=1000\$/);
});

test('pbkdf2.hash sha512 variant', async () => {
  const s = await pbkdf2.hash('pw', { ...FAST, hash: 'sha512' });
  assert.match(s, /^\$pbkdf2-sha512\$i=1000\$/);
});

test('pbkdf2.verify round-trip', async () => {
  const s = await pbkdf2.hash('secret', FAST);
  assert.equal(await pbkdf2.verify('secret', s), true);
  assert.equal(await pbkdf2.verify('other', s), false);
});

test('pbkdf2.verify: sha256 vs sha512 do not cross-verify', async () => {
  const s256 = await pbkdf2.hash('pw', { ...FAST, hash: 'sha256' });
  const s512 = await pbkdf2.hash('pw', { ...FAST, hash: 'sha512' });
  // Both must verify with their own algorithm
  assert.equal(await pbkdf2.verify('pw', s256), true);
  assert.equal(await pbkdf2.verify('pw', s512), true);
  // And the strings are different
  assert.notEqual(s256, s512);
});

test('pbkdf2.needsRehash: default params → false only at OWASP minimum', async () => {
  const s = await pbkdf2.hash('pw', { hash: 'sha256', iterations: 600_000 });
  assert.equal(pbkdf2.needsRehash(s), false);
});

test('pbkdf2.needsRehash: low iterations → true', async () => {
  const s = await pbkdf2.hash('pw', FAST);
  assert.equal(pbkdf2.needsRehash(s), true);
});

test('pbkdf2.needsRehash: sha256 vs sha512 target mismatch → true', async () => {
  const s = await pbkdf2.hash('pw', { hash: 'sha512', iterations: 210_000 });
  assert.equal(pbkdf2.needsRehash(s, { hash: 'sha256' }), true);
});

test('pbkdf2: unsupported hash rejected', async () => {
  await assert.rejects(pbkdf2.hash('pw', { hash: 'md5', iterations: 1000 }));
});
