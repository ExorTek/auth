import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { hashSecret, hashesMatch, mask, mint, parseApiKey } from '../src/token.js';

test('mint: returns wire key + id + hash', () => {
  const { key, id, hash } = mint('sk_live', null);
  assert.ok(key.startsWith('sk_live_'));
  assert.ok(key.includes(`_${id}_`));
  assert.equal(id.length, 26); // 16 random bytes → 26 chars crockford
  assert.equal(hash.length, 43); // 32-byte SHA-256 digest → 43 chars base64url
});

test('parseApiKey: 3-segment shape → { prefix, id, secret }', () => {
  const { key } = mint('sk_live', null);
  const parsed = parseApiKey(key);
  assert.ok(parsed);
  assert.equal(parsed.prefix, 'sk_live');
  assert.equal(parsed.id.length, 26);
  assert.equal(parsed.secret.length, 52);
});

test('parseApiKey: multi-segment prefix (svc_prod_v2) works', () => {
  const { key } = mint('svc_prod_v2', null);
  const parsed = parseApiKey(key);
  assert.equal(parsed.prefix, 'svc_prod_v2');
});

test('parseApiKey: non-string / garbage → null', () => {
  for (const v of [null, undefined, '', 'not-a-key', 'sk_live', 'sk_live_only', 42, {}]) {
    assert.equal(parseApiKey(v), null, `input: ${JSON.stringify(v)}`);
  }
});

test('hashSecret: pepper vs no-pepper produce different digests', () => {
  const secret = randomBytes(32);
  const a = hashSecret(secret, null);
  const b = hashSecret(secret, randomBytes(32));
  assert.notEqual(a, b);
});

test('hashesMatch: exact match → true, mismatch → false, length mismatch → false', () => {
  const secret = randomBytes(32);
  const hash = hashSecret(secret, null);
  assert.equal(hashesMatch(hash, hash), true);
  assert.equal(hashesMatch(hash, hash.replace(/./, 'X')), false);
  assert.equal(hashesMatch(hash + 'x', hash), false);
});

test('mask: <prefix>_<first6-of-id>…<last4-of-secret>', () => {
  const { key } = mint('sk_live', null);
  const parsed = parseApiKey(key);
  const masked = mask(key);
  assert.ok(masked.startsWith(`sk_live_${parsed.id.slice(0, 6)}…`));
  assert.ok(masked.endsWith(parsed.secret.slice(-4)));
});

test('mask: bogus input → placeholder / prefix only', () => {
  assert.equal(mask('bogus'), 'bog…');
  assert.equal(mask(42), '<invalid>');
});
