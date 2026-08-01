import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  paseto,
  encrypt,
  decrypt,
  sign,
  verify,
  generateKey,
  generateKeyPair,
  PasetoError,
  ErrorCode,
  SUPPORTED,
} from '../src/index.js';

// PACKAGE SURFACE

test('index exposes the public surface + frozen namespace', () => {
  for (const fn of [encrypt, decrypt, sign, verify, generateKey, generateKeyPair]) {
    assert.equal(typeof fn, 'function');
  }
  assert.equal(typeof paseto.encrypt, 'function');
  assert.ok(Object.isFrozen(paseto));
});

test('SUPPORTED lists the curated v4 set and nothing else', () => {
  assert.deepEqual([...SUPPORTED], ['v4.local', 'v4.public']);
});

// KEY GENERATION

test('generateKey returns a 32-byte symmetric key', () => {
  assert.equal(generateKey().length, 32);
});

test('generateKeyPair returns raw Ed25519 keys (64B secret ‖ 32B public)', () => {
  const { secretKey, publicKey } = generateKeyPair();
  assert.equal(secretKey.length, 64);
  assert.equal(publicKey.length, 32);
  // secretKey is seed ‖ public
  assert.ok(secretKey.subarray(32).equals(publicKey));
});

test('generateKey / generateKeyPair reject the wrong version', () => {
  assert.throws(
    () => generateKey('v4.public'),
    err => err instanceof PasetoError && err.code === ErrorCode.UNSUPPORTED_VERSION,
  );
  assert.throws(
    () => generateKeyPair('v4.local'),
    err => err instanceof PasetoError && err.code === ErrorCode.UNSUPPORTED_VERSION,
  );
});
