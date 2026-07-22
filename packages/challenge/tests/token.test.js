import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { DEFAULT_PREFIX, decode, newJti, sign } from '../src/token.js';

const SECRET = randomBytes(32);

test('newJti: returns 22-char base64url string of 16 random bytes', () => {
  const a = newJti();
  const b = newJti();
  assert.equal(typeof a, 'string');
  assert.match(a, /^[A-Za-z0-9_-]{22}$/);
  assert.notEqual(a, b);
});

test('sign: produces `chall_v1.<b64u payload>.<b64u tag>` shape', () => {
  const token = sign({ jti: 'abc', iat: 1, exp: 999 }, SECRET);
  const parts = token.split('.');
  assert.equal(parts.length, 3);
  assert.equal(parts[0], DEFAULT_PREFIX);
});

test('decode: round-trip returns the same payload', () => {
  const payload = { jti: 'x', iat: 100, exp: 200, userId: 'u1', meta: { a: 1 } };
  const res = decode(sign(payload, SECRET), SECRET);
  assert.deepEqual(res, { payload });
});

test('decode: wrong prefix → malformed', () => {
  const token = sign({ jti: 'x', iat: 1, exp: 2 }, SECRET);
  const swapped = token.replace(DEFAULT_PREFIX, 'chall_v9');
  assert.deepEqual(decode(swapped, SECRET), { reason: 'malformed' });
});

test('decode: tampered payload → bad_signature', () => {
  const token = sign({ jti: 'x', iat: 1, exp: 2 }, SECRET);
  const [p, payload, tag] = token.split('.');
  // Flip a bit in the payload — HMAC covers `prefix.payload`, so tag mismatches.
  const flipped = payload.replace(/./, c => (c === 'A' ? 'B' : 'A'));
  assert.deepEqual(decode(`${p}.${flipped}.${tag}`, SECRET), { reason: 'bad_signature' });
});

test('decode: non-string inputs → malformed', () => {
  for (const v of ['', 0, null, undefined, {}, []]) {
    assert.deepEqual(decode(v, SECRET), { reason: 'malformed' }, `input: ${JSON.stringify(v)}`);
  }
});

test('decode: tag with invalid base64url characters → malformed', () => {
  const token = sign({ jti: 'x', iat: 1, exp: 2 }, SECRET);
  const [p, payload] = token.split('.');
  assert.deepEqual(decode(`${p}.${payload}.!!!invalid!!!`, SECRET), { reason: 'malformed' });
});

test('decode: payload that decodes to an array → malformed', () => {
  // Craft a token where payload is a valid base64url of `[]` but tag matches.
  // We can build this by signing with an array payload and observing decode rejects it.
  // Since sign uses encodeJson which stringifies whatever we pass:
  const token = sign([], SECRET);
  const res = decode(token, SECRET);
  assert.deepEqual(res, { reason: 'malformed' });
});

test('sign/decode: custom prefix round-trips', () => {
  const payload = { jti: 'x', iat: 1, exp: 999 };
  const token = sign(payload, SECRET, 'server_challenge');
  assert.ok(token.startsWith('server_challenge.'));
  const good = decode(token, SECRET, 'server_challenge');
  assert.deepEqual(good, { payload });
});

test('decode: token minted with prefix A cannot be verified under prefix B', () => {
  const payload = { jti: 'x', iat: 1, exp: 999 };
  const token = sign(payload, SECRET, 'myapp_v1');
  // Wrong prefix → treated as malformed (prefix check fails before HMAC).
  assert.deepEqual(decode(token, SECRET, DEFAULT_PREFIX), { reason: 'malformed' });
  assert.deepEqual(decode(token, SECRET, 'other_prefix'), { reason: 'malformed' });
});
