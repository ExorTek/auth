import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, generateKeyPairSync } from 'node:crypto';

import { encryptJson, decryptJson, JweError, ErrorCode } from '../src/index.js';

const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const PAYLOAD = { sub: 'user-1', ok: true };

const isCode = code => err => err instanceof JweError && err.code === code;

test('General JSON single recipient round-trips', async () => {
  const jwe = await encryptJson(PAYLOAD, [{ key: rsa.publicKey, alg: 'RSA-OAEP-256', kid: 'r1' }], { enc: 'A256GCM' });
  assert.equal(jwe.recipients.length, 1);
  assert.equal(jwe.recipients[0].header.kid, 'r1');
  const { payload } = await decryptJson(jwe, rsa.privateKey, { alg: ['RSA-OAEP-256'], enc: ['A256GCM'] });
  assert.deepEqual(payload, PAYLOAD);
});

test('General JSON multi-recipient: either private key decrypts', async () => {
  const jwe = await encryptJson(
    PAYLOAD,
    [
      { key: rsa.publicKey, alg: 'RSA-OAEP-256' },
      { key: ec.publicKey, alg: 'ECDH-ES+A256KW' },
    ],
    { enc: 'A256GCM' },
  );
  assert.equal(jwe.recipients.length, 2);
  const opts = { alg: ['RSA-OAEP-256', 'ECDH-ES+A256KW'], enc: ['A256GCM'] };

  const viaRsa = await decryptJson(jwe, rsa.privateKey, opts);
  const viaEc = await decryptJson(jwe, ec.privateKey, opts);
  assert.deepEqual(viaRsa.payload, PAYLOAD);
  assert.deepEqual(viaEc.payload, PAYLOAD);
});

test('Flattened JSON input decrypts', async () => {
  const general = await encryptJson(PAYLOAD, [{ key: rsa.publicKey, alg: 'RSA-OAEP-256' }], { enc: 'A256GCM' });
  const flattened = {
    protected: general.protected,
    header: general.recipients[0].header,
    encrypted_key: general.recipients[0].encrypted_key,
    iv: general.iv,
    ciphertext: general.ciphertext,
    tag: general.tag,
  };
  const { payload } = await decryptJson(flattened, rsa.privateKey, { alg: ['RSA-OAEP-256'], enc: ['A256GCM'] });
  assert.deepEqual(payload, PAYLOAD);
});

test('additional authenticated data is bound into the tag', async () => {
  const jwe = await encryptJson(PAYLOAD, [{ key: rsa.publicKey, alg: 'RSA-OAEP-256' }], {
    enc: 'A256GCM',
    aad: 'context-42',
  });
  assert.equal(Buffer.from(jwe.aad, 'base64url').toString('utf8'), 'context-42');
  const { payload } = await decryptJson(jwe, rsa.privateKey, { alg: ['RSA-OAEP-256'], enc: ['A256GCM'] });
  assert.deepEqual(payload, PAYLOAD);

  jwe.aad = Buffer.from('tampered').toString('base64url');
  await assert.rejects(
    () => decryptJson(jwe, rsa.privateKey, { alg: ['RSA-OAEP-256'], enc: ['A256GCM'] }),
    isCode(ErrorCode.DECRYPTION_FAILED),
  );
});

test('dir works as the sole recipient but not alongside others', async () => {
  const key = randomBytes(32);
  const jwe = await encryptJson(PAYLOAD, [{ key, alg: 'dir' }], { enc: 'A256GCM' });
  const { payload } = await decryptJson(jwe, key, { alg: ['dir'], enc: ['A256GCM'] });
  assert.deepEqual(payload, PAYLOAD);

  await assert.rejects(
    () =>
      encryptJson(
        PAYLOAD,
        [
          { key, alg: 'dir' },
          { key: rsa.publicKey, alg: 'RSA-OAEP-256' },
        ],
        { enc: 'A256GCM' },
      ),
    isCode(ErrorCode.INVALID_ARGUMENT),
  );
});

test('decryptJson enforces the allowlist', async () => {
  const jwe = await encryptJson(PAYLOAD, [{ key: rsa.publicKey, alg: 'RSA-OAEP-256' }], { enc: 'A256GCM' });
  await assert.rejects(
    () => decryptJson(jwe, rsa.privateKey, { enc: ['A256GCM'] }),
    isCode(ErrorCode.MISSING_ALG_ALLOWLIST),
  );
  await assert.rejects(
    () => decryptJson(jwe, rsa.privateKey, { alg: ['dir'], enc: ['A256GCM'] }),
    isCode(ErrorCode.ALGORITHM_MISMATCH),
  );
});
