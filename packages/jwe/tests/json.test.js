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

test('decryptJson: recipient count and size are bounded before any unwrap', async () => {
  const jwe = await encryptJson(PAYLOAD, [{ key: rsa.publicKey, alg: 'RSA-OAEP-256' }], { enc: 'A256GCM' });
  const opts = { alg: ['RSA-OAEP-256'], enc: ['A256GCM'] };
  const flood = { ...jwe, recipients: Array.from({ length: 9 }, () => jwe.recipients[0]) };
  await assert.rejects(decryptJson(flood, rsa.privateKey, opts), isCode(ErrorCode.INVALID_TOKEN));
  await assert.rejects(
    decryptJson({ ...jwe, ciphertext: 'A'.repeat(70_000) }, rsa.privateKey, opts),
    isCode(ErrorCode.TOKEN_TOO_LARGE),
  );
});

test('decryptJson: an unprotected header may not shadow a protected value', async () => {
  const jwe = await encryptJson(PAYLOAD, [{ key: rsa.publicKey, alg: 'RSA-OAEP-256', kid: 'r1' }], {
    enc: 'A256GCM',
    header: { typ: 'secure+jwe' },
  });
  const opts = { alg: ['RSA-OAEP-256'], enc: ['A256GCM'] };
  const shadowed = {
    ...jwe,
    recipients: [{ ...jwe.recipients[0], header: { ...jwe.recipients[0].header, typ: 'evil' } }],
  };
  await assert.rejects(decryptJson(shadowed, rsa.privateKey, opts), isCode(ErrorCode.INVALID_HEADER));
  await assert.rejects(
    decryptJson({ ...jwe, unprotected: { crit: ['x'], x: 1 } }, rsa.privateKey, opts),
    isCode(ErrorCode.INVALID_HEADER),
  );

  const ok = await decryptJson(jwe, rsa.privateKey, opts);
  assert.equal(ok.protectedHeader.typ, 'secure+jwe');
  assert.equal(ok.protectedHeader.kid, undefined, 'unprotected members are not reported as protected');
  assert.equal(ok.unprotectedHeader.kid, 'r1');
  assert.equal(ok.header.kid, 'r1');
});

test('encryptJson refuses a header set both shared and per recipient', async () => {
  await assert.rejects(
    encryptJson(PAYLOAD, [{ key: rsa.publicKey, alg: 'RSA-OAEP-256', kid: 'r1' }], {
      enc: 'A256GCM',
      header: { kid: 'shared' },
    }),
    isCode(ErrorCode.INVALID_ARGUMENT),
  );
});
