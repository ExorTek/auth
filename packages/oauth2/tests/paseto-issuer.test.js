import assert from 'node:assert/strict';
import { test } from 'node:test';

import { generateKeyPair } from '@exortek/paseto';

import { pasetoIssuer } from '../src/server/index.js';

test('pasetoIssuer issues and introspects with typed v4 keys', async () => {
  const { secretKey, publicKey } = generateKeyPair();
  const issuer = pasetoIssuer({ secretKey, publicKey });
  const issued = await issuer.issue({ subject: 'u1', clientId: 'app', scope: ['read'] }, { issuer: 'https://as' });
  const { active, claims } = await issuer.introspect(issued.accessToken, { issuer: 'https://as' });
  assert.equal(active, true);
  assert.equal(claims.sub, 'u1');
});

test('pasetoIssuer refuses raw buffers and swapped key purposes', () => {
  const { secretKey, publicKey } = generateKeyPair();
  assert.throws(() => pasetoIssuer({ secretKey: secretKey.export(), publicKey: publicKey.export() }), {
    code: 'INVALID_ARGUMENT',
  });
  assert.throws(() => pasetoIssuer({ secretKey: publicKey, publicKey: secretKey }), { code: 'INVALID_ARGUMENT' });
});
