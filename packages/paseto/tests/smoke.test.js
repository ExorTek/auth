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

test('generateKey returns a typed v4 local key (32 bytes)', () => {
  const key = generateKey();
  assert.equal(key.version, 'v4');
  assert.equal(key.purpose, 'local');
  assert.equal(key.export().length, 32);
});

test('generateKeyPair returns typed Ed25519 keys (64B secret ‖ 32B public)', () => {
  const { secretKey, publicKey } = generateKeyPair();
  assert.equal(secretKey.purpose, 'secret');
  assert.equal(publicKey.purpose, 'public');
  assert.equal(secretKey.export().length, 64);
  assert.equal(publicKey.export().length, 32);
  // secretKey is seed ‖ public
  assert.ok(secretKey.export().subarray(32).equals(publicKey.export()));
  // Key bytes never leak through JSON.
  assert.deepEqual(JSON.parse(JSON.stringify(secretKey)), { version: 'v4', purpose: 'secret' });
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
