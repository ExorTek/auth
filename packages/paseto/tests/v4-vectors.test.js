/**
 * The official PASETO v4 test vectors
 * (paseto-standard/test-vectors/v4.json), run against the raw crypto
 * layer. Byte-exact token reproduction for the non-failing cases plus
 * the negative (`expect-fail`) cases. This is the ground truth for the
 * BLAKE2b + XChaCha20 + PAE + Ed25519 primitives.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { encryptRaw, decryptRaw } from '../src/internal/v4local.js';
import { signRaw, verifyRaw } from '../src/internal/v4public.js';

const VECTORS = JSON.parse(readFileSync(new URL('./v4-vectors.json', import.meta.url), 'utf8'));
const hex = h => Buffer.from(h, 'hex');

for (const vec of VECTORS.tests) {
  const isLocal = 'key' in vec;
  const footer = Buffer.from(vec.footer ?? '');
  const implicit = Buffer.from(vec['implicit-assertion'] ?? '');

  test(`${vec.name} (${isLocal ? 'local' : 'public'})${vec['expect-fail'] ? ' [expect-fail]' : ''}`, () => {
    if (isLocal) {
      if (vec['expect-fail']) {
        assert.throws(() => decryptRaw({ token: vec.token, key: hex(vec.key), implicit }));
        return;
      }
      const token = encryptRaw({
        message: Buffer.from(vec.payload),
        key: hex(vec.key),
        footer,
        implicit,
        nonce: hex(vec.nonce),
      });
      assert.equal(token, vec.token, 'encrypt must reproduce the vector token byte-for-byte');

      const { message } = decryptRaw({ token: vec.token, key: hex(vec.key), implicit });
      assert.equal(message.toString(), vec.payload);
    } else {
      if (vec['expect-fail']) {
        assert.throws(() => verifyRaw({ token: vec.token, publicKey: hex(vec['public-key']), implicit }));
        return;
      }
      const token = signRaw({
        message: Buffer.from(vec.payload),
        secretKey: hex(vec['secret-key']),
        footer,
        implicit,
      });
      assert.equal(token, vec.token, 'sign must reproduce the vector token byte-for-byte');

      const { message } = verifyRaw({ token: vec.token, publicKey: hex(vec['public-key']), implicit });
      assert.equal(message.toString(), vec.payload);
    }
  });
}
