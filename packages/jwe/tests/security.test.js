import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, generateKeyPairSync } from 'node:crypto';

import { encrypt, decrypt, JweError, ErrorCode } from '../src/index.js';

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

const isCode = code => err => err instanceof JweError && err.code === code;

/** Flip the first character of a compact segment to a different base64url char. */
function tamperSegment(token, index) {
  const parts = token.split('.');
  const seg = parts[index];
  const first = seg[0];
  parts[index] = (first === 'A' ? 'B' : 'A') + seg.slice(1);
  return parts.join('.');
}

// ALLOWLIST ENFORCEMENT

test('decrypt requires an alg allowlist', async () => {
  const key = randomBytes(32);
  const token = await encrypt({ a: 1 }, key, { alg: 'dir', enc: 'A256GCM' });
  await assert.rejects(() => decrypt(token, key, { enc: ['A256GCM'] }), isCode(ErrorCode.MISSING_ALG_ALLOWLIST));
  await assert.rejects(
    () => decrypt(token, key, { alg: [], enc: ['A256GCM'] }),
    isCode(ErrorCode.MISSING_ALG_ALLOWLIST),
  );
});

test('decrypt requires an enc allowlist', async () => {
  const key = randomBytes(32);
  const token = await encrypt({ a: 1 }, key, { alg: 'dir', enc: 'A256GCM' });
  await assert.rejects(() => decrypt(token, key, { alg: ['dir'] }), isCode(ErrorCode.MISSING_ENC_ALLOWLIST));
});

test('alg outside the allowlist is rejected', async () => {
  const kek = randomBytes(32);
  const token = await encrypt({ a: 1 }, kek, { alg: 'A256KW', enc: 'A256GCM' });
  await assert.rejects(
    () => decrypt(token, kek, { alg: ['dir'], enc: ['A256GCM'] }),
    isCode(ErrorCode.ALGORITHM_MISMATCH),
  );
});

test('enc outside the allowlist is rejected', async () => {
  const key = randomBytes(32);
  const token = await encrypt({ a: 1 }, key, { alg: 'dir', enc: 'A256GCM' });
  await assert.rejects(
    () => decrypt(token, key, { alg: ['dir'], enc: ['A128GCM'] }),
    isCode(ErrorCode.ENCRYPTION_MISMATCH),
  );
});

// RSA1_5 NEVER SUPPORTED

test('RSA1_5 is not a usable algorithm', async () => {
  await assert.rejects(
    () => encrypt({ a: 1 }, rsa.publicKey, { alg: 'RSA1_5', enc: 'A256GCM' }),
    isCode(ErrorCode.UNSUPPORTED_ALGORITHM),
  );
});

// INTEGRITY

test('tampered ciphertext fails authentication (GCM)', async () => {
  const key = randomBytes(32);
  const token = await encrypt({ a: 1 }, key, { alg: 'dir', enc: 'A256GCM' });
  await assert.rejects(
    () => decrypt(tamperSegment(token, 3), key, { alg: ['dir'], enc: ['A256GCM'] }),
    isCode(ErrorCode.DECRYPTION_FAILED),
  );
});

test('tampered tag fails authentication (GCM)', async () => {
  const key = randomBytes(32);
  const token = await encrypt({ a: 1 }, key, { alg: 'dir', enc: 'A256GCM' });
  await assert.rejects(
    () => decrypt(tamperSegment(token, 4), key, { alg: ['dir'], enc: ['A256GCM'] }),
    isCode(ErrorCode.DECRYPTION_FAILED),
  );
});

test('tampered ciphertext fails authentication (CBC-HMAC)', async () => {
  const key = randomBytes(64);
  const token = await encrypt({ a: 1 }, key, { alg: 'dir', enc: 'A256CBC-HS512' });
  await assert.rejects(
    () => decrypt(tamperSegment(token, 3), key, { alg: ['dir'], enc: ['A256CBC-HS512'] }),
    isCode(ErrorCode.DECRYPTION_FAILED),
  );
});

test('wrong RSA private key fails to unwrap', async () => {
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const token = await encrypt({ a: 1 }, rsa.publicKey, { alg: 'RSA-OAEP-256', enc: 'A256GCM' });
  await assert.rejects(
    () => decrypt(token, other.privateKey, { alg: ['RSA-OAEP-256'], enc: ['A256GCM'] }),
    isCode(ErrorCode.DECRYPTION_FAILED),
  );
});

// KEY VALIDATION

test('dir key of the wrong length is rejected', async () => {
  await assert.rejects(
    () => encrypt({ a: 1 }, randomBytes(16), { alg: 'dir', enc: 'A256GCM' }),
    isCode(ErrorCode.INVALID_KEY),
  );
});

test('RSA algorithm with a non-RSA key is rejected (alg confusion)', async () => {
  await assert.rejects(
    () => encrypt({ a: 1 }, ec.publicKey, { alg: 'RSA-OAEP', enc: 'A256GCM' }),
    isCode(ErrorCode.INVALID_KEY),
  );
});

test('decrypt with a public key where a private key is required', async () => {
  const token = await encrypt({ a: 1 }, rsa.publicKey, { alg: 'RSA-OAEP-256', enc: 'A256GCM' });
  await assert.rejects(
    () => decrypt(token, rsa.publicKey, { alg: ['RSA-OAEP-256'], enc: ['A256GCM'] }),
    isCode(ErrorCode.INVALID_KEY),
  );
});

// SIZE GUARD

test('oversized token is rejected before any crypto', async () => {
  const key = randomBytes(32);
  const token = await encrypt({ a: 1 }, key, { alg: 'dir', enc: 'A256GCM' });
  await assert.rejects(
    () => decrypt(token, key, { alg: ['dir'], enc: ['A256GCM'], maxTokenSize: 8 }),
    isCode(ErrorCode.TOKEN_TOO_LARGE),
  );
});

// EXPIRY

test('expired token is rejected, clockTolerance grants leeway', async () => {
  const key = randomBytes(32);
  const token = await encrypt({ a: 1 }, key, { alg: 'dir', enc: 'A256GCM', expiresIn: '-5s' });
  await assert.rejects(() => decrypt(token, key, { alg: ['dir'], enc: ['A256GCM'] }), isCode(ErrorCode.TOKEN_EXPIRED));
  const { payload } = await decrypt(token, key, { alg: ['dir'], enc: ['A256GCM'], clockTolerance: 60 });
  assert.equal(payload.a, 1);
});

// CRIT

test('unknown critical header is rejected unless declared known', async () => {
  const key = randomBytes(32);
  const token = await encrypt({ a: 1 }, key, { alg: 'dir', enc: 'A256GCM', header: { crit: ['exp2'], exp2: 1 } });
  await assert.rejects(
    () => decrypt(token, key, { alg: ['dir'], enc: ['A256GCM'] }),
    isCode(ErrorCode.CRIT_UNSUPPORTED),
  );
  const { payload } = await decrypt(token, key, { alg: ['dir'], enc: ['A256GCM'], knownCriticalHeaders: ['exp2'] });
  assert.equal(payload.a, 1);
});
