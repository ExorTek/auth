import { test } from 'node:test';
import assert from 'node:assert/strict';

import { verify } from '../src/index.js';

/**
 * RFC 7515 Appendix A test vectors — the spec pins each example JWS to
 * a specific header/payload/key/token combination. Verifying these
 * byte-for-byte proves cross-vendor interoperability at the compact
 * serialisation level.
 *
 * Note: A.1 (HS256) and A.2 (RS256) have deterministic signatures, so
 * both sign-side and verify-side can be pinned. A.3 (ES256) uses ECDSA
 * with a fresh nonce every time — we can only pin the verify side.
 */

// A.1 — HS256

test('RFC 7515 §A.1 — HS256 reference token verifies', async () => {
  // Copied verbatim from RFC 7515 §A.1.
  const token =
    'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9' +
    '.' +
    'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ' +
    '.' +
    'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

  const jwk = {
    kty: 'oct',
    k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
  };

  const { header, payload } = await verify(token, jwk, { alg: ['HS256'] });
  assert.equal(header.typ, 'JWT');
  assert.equal(header.alg, 'HS256');
  assert.equal(payload.iss, 'joe');
  assert.equal(payload.exp, 1300819380);
  assert.equal(payload['http://example.com/is_root'], true);
});

test('RFC 7515 §A.1 — HS256 reference token has an oct JWK secret', async () => {
  // The literal secret bytes from the RFC (§A.1.1) are:
  //   { 3, 35, 53, 75, ... }  — 64 bytes total.
  // Just sanity-check that the base64url decode length matches.
  const jwk = {
    kty: 'oct',
    k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
  };
  const bytes = Buffer.from(jwk.k, 'base64url');
  assert.equal(bytes.length, 64);
});

// A.2 — RS256

test('RFC 7515 §A.2 — RS256 reference token verifies', async () => {
  const token =
    'eyJhbGciOiJSUzI1NiJ9' +
    '.' +
    'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ' +
    '.' +
    'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7' +
    'AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4' +
    'BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K' +
    '0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv' +
    'hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB' +
    'p0igcN_IoypGlUPQGe77Rw';

  // JWK from §A.2.1 (public modulus + exponent).
  const jwk = {
    kty: 'RSA',
    n:
      'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx' +
      'HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs' +
      'D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH' +
      'SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV' +
      'MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8' +
      'NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
    e: 'AQAB',
  };

  const { header, payload } = await verify(token, jwk, { alg: ['RS256'] });
  assert.equal(header.alg, 'RS256');
  assert.equal(payload.iss, 'joe');
  assert.equal(payload.exp, 1300819380);
  assert.equal(payload['http://example.com/is_root'], true);
});

// A.3 — ES256

test('RFC 7515 §A.3 — ES256 reference token verifies', async () => {
  const token =
    'eyJhbGciOiJFUzI1NiJ9' +
    '.' +
    'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ' +
    '.' +
    'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS' +
    'lSApmWQxfKTUJqPP3-Kg6NU1Q';

  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  };

  const { header, payload } = await verify(token, jwk, { alg: ['ES256'] });
  assert.equal(header.alg, 'ES256');
  assert.equal(payload.iss, 'joe');
});

// A.4 — ES512

test('RFC 7515 §A.4 — ES512 reference token verifies', async () => {
  const token =
    'eyJhbGciOiJFUzUxMiJ9' +
    '.' +
    'UGF5bG9hZA' +
    '.' +
    'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq' +
    'wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp' +
    'EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn';

  const jwk = {
    kty: 'EC',
    crv: 'P-521',
    x: 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_' + 'NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
    y: 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl' + 'y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
  };

  const { header, payload } = await verify(token, jwk, { alg: ['ES512'] });
  assert.equal(header.alg, 'ES512');
  // Payload segment `UGF5bG9hZA` is the ASCII string "Payload" (RFC 7515 §A.4).
  assert.ok(Buffer.isBuffer(payload));
  assert.equal(payload.toString('utf8'), 'Payload');
});
