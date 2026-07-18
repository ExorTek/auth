import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';

import { hash } from '../src/hash.js';
import { hmac } from '../src/hmac.js';
import { randomBuffer } from '../src/random.js';

test('hash: sha256 hex matches node:crypto direct', () => {
  const data = 'the quick brown fox';
  const ours = hash('sha256', data, 'hex');
  const theirs = createHash('sha256').update(data).digest('hex');
  assert.equal(ours, theirs);
});

test('hash: encoding omitted → raw Buffer', () => {
  const bytes = hash('sha256', 'x');
  assert.ok(Buffer.isBuffer(bytes));
  assert.equal(bytes.length, 32);
});

test('hmac: sha256 hex matches node:crypto direct', () => {
  const secret = Buffer.from('super-secret');
  const data = 'payload';
  const ours = hmac('sha256', secret, data, 'hex');
  const theirs = createHmac('sha256', secret).update(data).digest('hex');
  assert.equal(ours, theirs);
});

test('randomBuffer: returns a Buffer of the requested length', () => {
  const b = randomBuffer(24);
  assert.ok(Buffer.isBuffer(b));
  assert.equal(b.length, 24);
});

test('randomBuffer: consecutive calls differ', () => {
  const a = randomBuffer(32);
  const b = randomBuffer(32);
  assert.notEqual(a.toString('hex'), b.toString('hex'));
});
