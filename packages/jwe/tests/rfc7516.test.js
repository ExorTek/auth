import { test } from 'node:test';
import assert from 'node:assert/strict';

import { decrypt, decodeProtectedHeader } from '../src/index.js';

// RFC 7516 Appendix A.3 — a complete worked example for
// A128KW (AES Key Wrap) + A128CBC-HS256. Decrypting the spec's own
// Compact Serialization with its shared key proves our AES-KW unwrap,
// AES-CBC-HMAC content decryption, and AAD construction interoperate
// with the standard rather than merely with themselves.

const A3_JWE = [
  'eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0',
  '6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ',
  'AxY8DCtDaGlsbGljb3RoZQ',
  'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY',
  'U0m_YmjN04DJvceFICbCVQ',
].join('.');

// Appendix A.3.1 — the shared symmetric key as a JWK "k" value.
const A3_KEY = { kty: 'oct', k: 'GawgguFyGrWKav7AX4VKUg' };

test('RFC 7516 A.3 — decrypts the spec vector (A128KW + A128CBC-HS256)', async () => {
  const header = decodeProtectedHeader(A3_JWE);
  assert.deepEqual(header, { alg: 'A128KW', enc: 'A128CBC-HS256' });

  const { payload } = await decrypt(A3_JWE, A3_KEY, { alg: ['A128KW'], enc: ['A128CBC-HS256'] });
  const text = Buffer.isBuffer(payload) ? payload.toString('utf8') : payload;
  assert.equal(text, 'Live long and prosper.');
});
