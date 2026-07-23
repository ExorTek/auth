import { describe, test, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createRemoteJWKS } from '../src/remote.js';
import { JwksError, ErrorCode } from '../src/errors.js';

const SAMPLE_EC_JWK = {
  kty: 'EC',
  crv: 'P-256',
  kid: 'k1',
  use: 'sig',
  alg: 'ES256',
  x: '5YS4Mvk2pzkk0nTsQYZlSSLui9rRmoidouWxW0uvrU8',
  y: 'IcN0gCXagiHkKeGooEGoF6eeOZiSgqsGUzrmDkFGOLU',
};

function fakeJwksResponse(keys = [SAMPLE_EC_JWK]) {
  return { keys };
}

function mockFetch(impl) {
  return mock.method(globalThis, 'fetch', impl);
}

describe('createRemoteJWKS — validation', () => {
  test('rejects empty uri', () => {
    assert.throws(() => createRemoteJWKS(''), /uri/);
  });

  test('rejects non-http/https protocol', () => {
    assert.throws(() => createRemoteJWKS('file:///etc/passwd'), /http or https/);
  });

  test('rejects http without allowInsecure', () => {
    assert.throws(() => createRemoteJWKS('http://example.com/jwks'), /https/);
  });

  test('allows http with allowInsecure', () => {
    const resolver = createRemoteJWKS('http://example.com/jwks', { allowInsecure: true });
    assert.ok(typeof resolver === 'function');
  });

  test('allows https by default', () => {
    const resolver = createRemoteJWKS('https://example.com/jwks');
    assert.ok(typeof resolver === 'function');
  });
});

describe('resolver — fetch and cache', () => {
  afterEach(() => mock.restoreAll());

  test('initial resolve fetches and returns key', async () => {
    const fn = mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const resolver = createRemoteJWKS('https://example.com/jwks');
    const key = await resolver({ kid: 'k1', alg: 'ES256' });
    assert.equal(key.type, 'public');
    assert.equal(fn.mock.callCount(), 1);
  });

  test('second resolve uses cache (no second fetch)', async () => {
    const fn = mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const resolver = createRemoteJWKS('https://example.com/jwks');
    await resolver({ kid: 'k1' });
    await resolver({ kid: 'k1' });
    assert.equal(fn.mock.callCount(), 1);
  });

  test('stale cache triggers refetch', async () => {
    const fn = mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const resolver = createRemoteJWKS('https://example.com/jwks', {
      cacheTtl: 1,
      cooldownMs: 0,
    });
    await resolver({ kid: 'k1' });
    await new Promise(r => setTimeout(r, 10));
    await resolver({ kid: 'k1' });
    assert.equal(fn.mock.callCount(), 2);
  });
});

describe('resolver — kid-miss refetch', () => {
  afterEach(() => mock.restoreAll());

  test('refetches on unknown kid when cooldown allows', async () => {
    let keys = [SAMPLE_EC_JWK];
    const fn = mockFetch(async () => ({ ok: true, json: async () => ({ keys }) }));

    const resolver = createRemoteJWKS('https://example.com/jwks', { cooldownMs: 0 });

    await resolver({ kid: 'k1' });
    assert.equal(fn.mock.callCount(), 1);

    keys = [SAMPLE_EC_JWK, { ...SAMPLE_EC_JWK, kid: 'k2' }];

    const key2 = await resolver({ kid: 'k2' });
    assert.equal(key2.type, 'public');
    assert.equal(fn.mock.callCount(), 2);
  });

  test('cooldown prevents rapid refetches', async () => {
    const fn = mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));

    const resolver = createRemoteJWKS('https://example.com/jwks', { cooldownMs: 60_000 });

    await resolver({ kid: 'k1' });
    assert.equal(fn.mock.callCount(), 1);

    const err = await resolver({ kid: 'unknown' }).catch(e => e);
    assert.ok(err instanceof JwksError);
    assert.equal(err.code, ErrorCode.KID_NOT_FOUND);
    assert.equal(fn.mock.callCount(), 1);
  });
});

describe('resolver — error handling', () => {
  afterEach(() => mock.restoreAll());

  test('throws KID_NOT_FOUND for missing kid header', async () => {
    mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const resolver = createRemoteJWKS('https://example.com/jwks');
    const err = await resolver({}).catch(e => e);
    assert.ok(err instanceof JwksError);
    assert.equal(err.code, ErrorCode.KID_NOT_FOUND);
  });

  test('throws FETCH_FAILED on non-ok response', async () => {
    mockFetch(async () => ({ ok: false, status: 500, json: async () => ({}) }));
    const resolver = createRemoteJWKS('https://example.com/jwks');
    const err = await resolver({ kid: 'k1' }).catch(e => e);
    assert.ok(err instanceof JwksError);
    assert.equal(err.code, ErrorCode.FETCH_FAILED);
  });

  test('throws FETCH_FAILED on invalid response body', async () => {
    mockFetch(async () => ({ ok: true, json: async () => ({ notKeys: [] }) }));
    const resolver = createRemoteJWKS('https://example.com/jwks');
    const err = await resolver({ kid: 'k1' }).catch(e => e);
    assert.ok(err instanceof JwksError);
    assert.equal(err.code, ErrorCode.FETCH_FAILED);
  });

  test('fetch failure preserves old cache', async () => {
    let shouldFail = false;
    const fn = mockFetch(async () => {
      if (shouldFail) throw new Error('network down');
      return { ok: true, json: async () => fakeJwksResponse() };
    });

    const resolver = createRemoteJWKS('https://example.com/jwks', {
      cacheTtl: 1,
      cooldownMs: 0,
    });

    await resolver({ kid: 'k1' });
    assert.equal(fn.mock.callCount(), 1);

    await new Promise(r => setTimeout(r, 10));
    shouldFail = true;

    const err = await resolver({ kid: 'k1' }).catch(e => e);
    assert.ok(err instanceof Error);
    assert.equal(fn.mock.callCount(), 2);

    shouldFail = false;
    const key = await resolver({ kid: 'k1' });
    assert.equal(key.type, 'public');
    assert.equal(fn.mock.callCount(), 3);
  });

  test('cooldown applies after failed fetch too', async () => {
    let shouldFail = true;
    const fn = mockFetch(async () => {
      if (shouldFail) throw new Error('network down');
      return { ok: true, json: async () => fakeJwksResponse() };
    });

    const resolver = createRemoteJWKS('https://example.com/jwks', { cooldownMs: 60_000 });

    await resolver({ kid: 'k1' }).catch(() => {});
    assert.equal(fn.mock.callCount(), 1);

    shouldFail = false;
    const err = await resolver({ kid: 'k1' }).catch(e => e);
    assert.ok(err instanceof JwksError);
    assert.equal(err.code, ErrorCode.FETCH_FAILED);
    assert.equal(fn.mock.callCount(), 1);
  });
});

describe('resolver — alg cross-check', () => {
  afterEach(() => mock.restoreAll());

  test('throws on alg mismatch', async () => {
    mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const resolver = createRemoteJWKS('https://example.com/jwks');
    const err = await resolver({ kid: 'k1', alg: 'RS256' }).catch(e => e);
    assert.ok(err instanceof JwksError);
    assert.equal(err.code, ErrorCode.KID_NOT_FOUND);
    assert.ok(err.message.includes('alg mismatch'));
  });

  test('passes when alg matches', async () => {
    mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const resolver = createRemoteJWKS('https://example.com/jwks');
    const key = await resolver({ kid: 'k1', alg: 'ES256' });
    assert.equal(key.type, 'public');
  });

  test('passes when alg is not provided', async () => {
    mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const resolver = createRemoteJWKS('https://example.com/jwks');
    const key = await resolver({ kid: 'k1' });
    assert.equal(key.type, 'public');
  });
});

describe('resolver — coalescing', () => {
  afterEach(() => mock.restoreAll());

  test('concurrent calls coalesce into single fetch', async () => {
    let callCount = 0;
    mockFetch(async () => {
      callCount++;
      await new Promise(r => setTimeout(r, 50));
      return { ok: true, json: async () => fakeJwksResponse() };
    });

    const resolver = createRemoteJWKS('https://example.com/jwks');

    const [k1, k2] = await Promise.all([
      resolver({ kid: 'k1' }),
      resolver({ kid: 'k1' }),
    ]);

    assert.equal(k1.type, 'public');
    assert.equal(k2.type, 'public');
    assert.equal(callCount, 1);
  });
});

describe('staleWhileError', () => {
  afterEach(() => mock.restoreAll());

  test('serves stale cache when refetch fails', async () => {
    let shouldFail = false;
    mockFetch(async () => {
      if (shouldFail) throw new Error('network down');
      return { ok: true, json: async () => fakeJwksResponse() };
    });

    const resolver = createRemoteJWKS('https://example.com/jwks', {
      staleWhileError: true,
      cacheTtl: 1,
      cooldownMs: 0,
    });

    await resolver({ kid: 'k1' });
    await new Promise(r => setTimeout(r, 10));
    shouldFail = true;

    const key = await resolver({ kid: 'k1' });
    assert.equal(key.type, 'public');
  });

  test('still throws when no cache exists', async () => {
    mockFetch(async () => {
      throw new Error('network down');
    });

    const resolver = createRemoteJWKS('https://example.com/jwks', {
      staleWhileError: true,
    });

    const err = await resolver({ kid: 'k1' }).catch(e => e);
    assert.ok(err instanceof Error);
  });
});

describe('onInvalidKey callback', () => {
  afterEach(() => mock.restoreAll());

  test('called on kid not found', async () => {
    mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const calls = [];
    const resolver = createRemoteJWKS('https://example.com/jwks', {
      cooldownMs: 60_000,
      onInvalidKey: (header, err) => calls.push({ header, err }),
    });

    await resolver({ kid: 'k1' });
    await resolver({ kid: 'missing' }).catch(() => {});

    assert.equal(calls.length, 1);
    assert.equal(calls[0].header.kid, 'missing');
    assert.ok(calls[0].err instanceof JwksError);
  });

  test('called on alg mismatch', async () => {
    mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const calls = [];
    const resolver = createRemoteJWKS('https://example.com/jwks', {
      onInvalidKey: (header, err) => calls.push({ header, err }),
    });

    await resolver({ kid: 'k1', alg: 'RS256' }).catch(() => {});

    assert.equal(calls.length, 1);
    assert.ok(calls[0].err.message.includes('alg mismatch'));
  });
});

describe('reload and cachedKids', () => {
  afterEach(() => mock.restoreAll());

  test('reload clears cache and refetches', async () => {
    const fn = mockFetch(async () => ({ ok: true, json: async () => fakeJwksResponse() }));
    const resolver = createRemoteJWKS('https://example.com/jwks', { cooldownMs: 0 });
    await resolver({ kid: 'k1' });
    assert.deepEqual(resolver.cachedKids(), ['k1']);

    await resolver.reload();
    assert.equal(fn.mock.callCount(), 2);
    assert.deepEqual(resolver.cachedKids(), ['k1']);
  });

  test('cachedKids returns empty before first fetch', () => {
    const resolver = createRemoteJWKS('https://example.com/jwks');
    assert.deepEqual(resolver.cachedKids(), []);
  });
});

describe('LRU eviction', () => {
  afterEach(() => mock.restoreAll());

  test('recently accessed key survives eviction', async () => {
    const keys = [
      { ...SAMPLE_EC_JWK, kid: 'k1' },
      { ...SAMPLE_EC_JWK, kid: 'k2' },
      { ...SAMPLE_EC_JWK, kid: 'k3' },
    ];
    mockFetch(async () => ({ ok: true, json: async () => ({ keys }) }));

    const resolver = createRemoteJWKS('https://example.com/jwks', { maxCacheKeys: 2 });

    await resolver({ kid: 'k1' });
    await resolver({ kid: 'k2' });
    await resolver({ kid: 'k1' });
    await resolver({ kid: 'k3' });

    const key1 = await resolver({ kid: 'k1' });
    assert.equal(key1.type, 'public');
  });
});
