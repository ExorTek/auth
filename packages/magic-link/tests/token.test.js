import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { DEFAULT_PREFIX, decode, hashEmailValue, newId, sign } from '../src/token.js';

const SECRET = randomBytes(32);

test('newId: 22-char base64url of 16 random bytes', () => {
  const a = newId();
  const b = newId();
  assert.match(a, /^[A-Za-z0-9_-]{22}$/);
  assert.notEqual(a, b);
});

test('sign + decode round-trip returns the same payload', () => {
  const payload = { id: 'x', iat: 100, exp: 200, eh: 'yz' };
  const token = sign(payload, SECRET);
  const res = decode(token, SECRET);
  assert.deepEqual(res, { payload });
});

test('decode: wrong prefix → malformed', () => {
  const token = sign({ id: 'x', iat: 1, exp: 2 }, SECRET);
  const swapped = token.replace(DEFAULT_PREFIX, 'mlink_v9');
  assert.deepEqual(decode(swapped, SECRET), { reason: 'malformed' });
});

test('decode: tampered payload → bad_signature', () => {
  const token = sign({ id: 'x', iat: 1, exp: 2 }, SECRET);
  const [p, payload, tag] = token.split('.');
  const flipped = payload.replace(/./, c => (c === 'A' ? 'B' : 'A'));
  assert.deepEqual(decode(`${p}.${flipped}.${tag}`, SECRET), { reason: 'bad_signature' });
});

test('decode: non-string / empty → malformed', () => {
  for (const v of ['', 0, null, undefined, {}, []]) {
    assert.deepEqual(decode(v, SECRET), { reason: 'malformed' }, `input: ${JSON.stringify(v)}`);
  }
});

test('decode: invalid base64url tag → malformed', () => {
  const token = sign({ id: 'x', iat: 1, exp: 2 }, SECRET);
  const [p, payload] = token.split('.');
  assert.deepEqual(decode(`${p}.${payload}.!!invalid!!`, SECRET), { reason: 'malformed' });
});

test('sign + decode: custom prefix round-trips', () => {
  const payload = { id: 'x', iat: 1, exp: 2 };
  const token = sign(payload, SECRET, 'login_v1');
  assert.ok(token.startsWith('login_v1.'));
  assert.deepEqual(decode(token, SECRET, 'login_v1'), { payload });
});

test('decode: token with prefix A cannot be verified under prefix B', () => {
  const token = sign({ id: 'x', iat: 1, exp: 2 }, SECRET, 'a_v1');
  assert.deepEqual(decode(token, SECRET, DEFAULT_PREFIX), { reason: 'malformed' });
  assert.deepEqual(decode(token, SECRET, 'b_v1'), { reason: 'malformed' });
});

test('hashEmailValue: deterministic + case-sensitive', () => {
  const a = hashEmailValue(SECRET, 'user@example.com');
  const b = hashEmailValue(SECRET, 'user@example.com');
  const c = hashEmailValue(SECRET, 'USER@example.com');
  assert.equal(a, b);
  assert.notEqual(a, c);
});
