import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import { createKeyResolver } from '../src/key-resolver.js';

const { publicKey } = generateKeyPairSync('ed25519');

// Identity-ish normalize: returns the KeyObject it is handed, records calls.
const calls = [];
const resolveKey = createKeyResolver((keyInput, alg, use) => {
  calls.push({ keyInput, alg, use });
  if (keyInput && typeof keyInput === 'object' && 'key' in keyInput) {
    return keyInput.key;
  }
  return keyInput;
});

test('passes single key straight to normalize', async () => {
  calls.length = 0;
  const out = await resolveKey(publicKey, {}, 'EdDSA');
  assert.equal(out, publicKey);
  assert.deepEqual(calls[0].use, 'verify');
});

test('function input: awaited then normalised', async () => {
  const out = await resolveKey(async header => (header.kid === 'a' ? publicKey : null), { kid: 'a' }, 'EdDSA');
  assert.equal(out, publicKey);
});

test('array + kid: picks the matching candidate', async () => {
  const out = await resolveKey(
    [
      { kid: 'x', key: publicKey },
      { kid: 'y', key: null },
    ],
    { kid: 'x' },
    'EdDSA',
  );
  assert.equal(out, publicKey);
});

test('array without kid: single-element bypass, multi-element rejects', async () => {
  const out = await resolveKey([{ kid: 'x', key: publicKey }], {}, 'EdDSA');
  assert.equal(out, publicKey);
  await assert.rejects(resolveKey([{ kid: 'x' }, { kid: 'y' }], {}, 'EdDSA'), err => err.keyNotFound === true);
});

test('missing-key failures carry the keyNotFound marker', async () => {
  await assert.rejects(resolveKey([], {}, 'EdDSA'), err => err.keyNotFound === true);
  await assert.rejects(resolveKey([{ kid: 'a' }], { kid: 'zzz' }, 'EdDSA'), err => err.keyNotFound === true);
});

test('normalize errors propagate untouched', async () => {
  const boom = new Error('typed package error');
  const r = createKeyResolver(() => {
    throw boom;
  });
  await assert.rejects(r(publicKey, {}, 'EdDSA'), err => err === boom && err.keyNotFound === undefined);
});
