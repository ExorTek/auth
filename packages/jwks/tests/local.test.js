import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createLocalKeySet } from '../src/local.js';
import { JwksError, ErrorCode } from '../src/errors.js';

describe('createLocalKeySet', () => {
  test('creates a key set with ES256 + EdDSA', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256' }, { alg: 'EdDSA' }]);
    assert.equal(ks.size, 2);
    assert.equal(ks.kids.length, 2);
  });

  test('toJSON returns only public keys (no d parameter)', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'pub-test' }]);
    const jwks = ks.toJSON();
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].kid, 'pub-test');
    assert.equal(jwks.keys[0].d, undefined);
  });

  test('getSigningKey filters by alg', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256' }, { alg: 'EdDSA' }]);
    const es = ks.getSigningKey('ES256');
    assert.equal(es.alg, 'ES256');
    const ed = ks.getSigningKey('EdDSA');
    assert.equal(ed.alg, 'EdDSA');
    assert.equal(ks.getSigningKey('RS256'), null);
  });

  test('getSigningKey without alg returns newest active key', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256' }, { alg: 'EdDSA' }]);
    const newest = ks.getSigningKey();
    assert.equal(newest.alg, 'EdDSA');
  });

  test('rejects empty specs', async () => {
    await assert.rejects(() => createLocalKeySet([]), /non-empty array/);
  });

  test('rejects unsupported algorithm', async () => {
    await assert.rejects(() => createLocalKeySet([{ alg: 'INVALID' }]), /unsupported algorithm/);
  });

  test('explicit kid is used', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'my-kid' }]);
    assert.equal(ks.kids[0], 'my-kid');
  });
});

describe('rotate', () => {
  test('retires old key and creates new one', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'old' }]);
    const rotated = await ks.rotate({ alg: 'ES256' });
    assert.notEqual(rotated.kid, 'old');
    assert.equal(ks.size, 2);
    const sigKey = ks.getSigningKey('ES256');
    assert.equal(sigKey.kid, rotated.kid);
  });

  test('retired key stays in toJSON during grace period', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'old' }]);
    await ks.rotate({ alg: 'ES256' });
    const jwks = ks.toJSON();
    assert.equal(jwks.keys.length, 2);
    const kids = jwks.keys.map(k => k.kid);
    assert.ok(kids.includes('old'));
  });

  test('retired key is swept after grace period', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'old' }], { gracePeriod: 1 });
    await ks.rotate({ alg: 'ES256' });
    await new Promise(r => setTimeout(r, 10));
    assert.equal(ks.size, 1);
    const jwks = ks.toJSON();
    assert.equal(jwks.keys.length, 1);
    assert.notEqual(jwks.keys[0].kid, 'old');
  });

  test('resolve still works on retired key within grace', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'old' }], { gracePeriod: '1h' });
    await ks.rotate({ alg: 'ES256' });
    const key = await ks.resolve({ kid: 'old' });
    assert.equal(key.type, 'public');
  });

  test('explicit kid on rotate', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256' }]);
    const rotated = await ks.rotate({ alg: 'ES256', kid: 'new-kid' });
    assert.equal(rotated.kid, 'new-kid');
  });
});

describe('addKey', () => {
  test('adds an existing key pair', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'k1' }]);
    const sigKey = ks.getSigningKey('ES256');
    const ks2 = await createLocalKeySet([{ alg: 'EdDSA' }]);
    ks2.addKey({ ...sigKey.privateJwk, kid: 'imported', alg: 'ES256' });
    assert.equal(ks2.size, 2);
    assert.ok(ks2.kids.includes('imported'));
  });

  test('throws on duplicate kid', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'dup' }]);
    const sigKey = ks.getSigningKey('ES256');
    assert.throws(() => ks.addKey({ ...sigKey.privateJwk, kid: 'dup', alg: 'ES256' }), /already exists/);
  });

  test('throws without kid', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256' }]);
    assert.throws(() => ks.addKey({ alg: 'ES256' }), /kid/);
  });

  test('throws without alg', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256' }]);
    assert.throws(() => ks.addKey({ kid: 'x' }), /alg/);
  });
});

describe('resolve', () => {
  test('resolves by kid', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'r1' }]);
    const key = await ks.resolve({ kid: 'r1' });
    assert.equal(key.type, 'public');
  });

  test('throws KID_NOT_FOUND for unknown kid', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'r1' }]);
    const err = await ks.resolve({ kid: 'unknown' }).catch(e => e);
    assert.ok(err instanceof JwksError);
    assert.equal(err.code, ErrorCode.KID_NOT_FOUND);
  });

  test('throws on alg mismatch', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'r1' }]);
    const err = await ks.resolve({ kid: 'r1', alg: 'RS256' }).catch(e => e);
    assert.ok(err instanceof JwksError);
    assert.equal(err.code, ErrorCode.KID_NOT_FOUND);
    assert.ok(err.message.includes('alg mismatch'));
  });
});

describe('handler', () => {
  test('returns JSON with correct headers', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'h1' }]);
    const handler = ks.handler();
    let status, headers, body;
    const res = {
      writeHead(s, h) {
        status = s;
        headers = h;
      },
      end(b) {
        body = b;
      },
    };
    handler({}, res);
    assert.equal(status, 200);
    assert.equal(headers['content-type'], 'application/json; charset=utf-8');
    assert.equal(headers['cache-control'], 'public, max-age=300');
    const parsed = JSON.parse(body);
    assert.equal(parsed.keys.length, 1);
    assert.equal(parsed.keys[0].kid, 'h1');
  });

  test('custom cacheControl option', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256' }]);
    const handler = ks.handler({ cacheControl: 'no-cache' });
    let headers;
    handler(
      {},
      {
        writeHead(_, h) {
          headers = h;
        },
        end() {},
      },
    );
    assert.equal(headers['cache-control'], 'no-cache');
  });
});

describe('kids and size consistency', () => {
  test('both sweep retired keys', async () => {
    const ks = await createLocalKeySet([{ alg: 'ES256', kid: 'x' }], { gracePeriod: 1 });
    await ks.rotate({ alg: 'ES256' });
    await new Promise(r => setTimeout(r, 10));
    assert.equal(ks.size, 1);
    assert.equal(ks.kids.length, 1);
    assert.notEqual(ks.kids[0], 'x');
  });
});
