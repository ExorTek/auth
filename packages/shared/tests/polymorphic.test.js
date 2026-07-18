import { test } from 'node:test';
import assert from 'node:assert/strict';

import { resolveOrCall, resolveHashFn, resolveEncoding, randomBuffer } from '../src/polymorphic.js';

test('resolveOrCall: passes value through unchanged', async () => {
  assert.equal(await resolveOrCall(42), 42);
  assert.equal(await resolveOrCall('x'), 'x');
});

test('resolveOrCall: invokes fn with args, awaits result', async () => {
  assert.equal(await resolveOrCall((a, b) => a + b, 2, 3), 5);
  assert.equal(await resolveOrCall(async () => 'y'), 'y');
});

test('resolveHashFn: default preset is sha256 hex', async () => {
  const h = resolveHashFn(undefined);
  assert.match(await h('x'), /^[0-9a-f]{64}$/);
});

test('resolveHashFn: string preset picks the algo', async () => {
  const h384 = resolveHashFn('sha384');
  assert.match(await h384('x'), /^[0-9a-f]{96}$/);
});

test('resolveHashFn: custom fn wins over preset', async () => {
  const h = resolveHashFn(async input => `custom:${input}`);
  assert.equal(await h('abc'), 'custom:abc');
});

test('resolveEncoding: base64url default', () => {
  const enc = resolveEncoding(undefined);
  assert.equal(enc(Buffer.from([255, 0, 128])), '_wCA');
});

test('resolveEncoding: hex preset', () => {
  const enc = resolveEncoding('hex');
  assert.equal(enc(Buffer.from([0xde, 0xad])), 'dead');
});

test('resolveEncoding: uuid preset ignores bytes, emits v4 UUID', () => {
  const enc = resolveEncoding('uuid');
  const uuid = enc(Buffer.alloc(0));
  assert.match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('resolveEncoding: unknown preset throws', () => {
  assert.throws(() => resolveEncoding('rot13'), /unknown encoding/);
});

test('polymorphic re-exports randomBuffer from crypto/random', () => {
  const b = randomBuffer(8);
  assert.equal(b.length, 8);
});
