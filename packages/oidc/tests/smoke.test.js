import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ErrorCode, OidcError, createClient, createProvider } from '../src/index.js';
import { createClient as createClientSub } from '../src/client/index.js';
import { createProvider as createProviderSub } from '../src/provider/index.js';

describe('@exortek/oidc scaffold', () => {
  it('exposes the public surface from the root barrel', () => {
    assert.equal(typeof createClient, 'function');
    assert.equal(typeof createProvider, 'function');
    assert.equal(typeof OidcError, 'function');
    assert.equal(ErrorCode.INVALID_ARGUMENT, 'INVALID_ARGUMENT');
    assert.equal(ErrorCode.NOT_IMPLEMENTED, 'NOT_IMPLEMENTED');
  });

  it('subpath entries resolve to the same factories', () => {
    assert.equal(createClientSub, createClient);
    assert.equal(createProviderSub, createProvider);
  });

  describe('createClient', () => {
    const base = {
      issuer: 'https://accounts.example.com',
      clientId: 'abc',
      redirectUri: 'https://app.example.com/callback',
    };

    it('defaults the scope to include openid', () => {
      const client = createClient(base);
      assert.deepEqual(client.scope, ['openid']);
      assert.equal(client.issuer, base.issuer);
      assert.equal(client.clientId, base.clientId);
    });

    it('always keeps openid in a supplied scope', () => {
      const client = createClient({ ...base, scope: ['email', 'profile'] });
      assert.ok(client.scope.includes('openid'));
      assert.ok(client.scope.includes('email'));
    });

    it('rejects a missing issuer with INVALID_ARGUMENT', () => {
      assert.throws(
        () => createClient({ ...base, issuer: '' }),
        err => {
          assert.ok(err instanceof OidcError);
          assert.equal(err.code, ErrorCode.INVALID_ARGUMENT);
          assert.equal(err.status, 400);
          return true;
        },
      );
    });

    it('rejects a non-object config', () => {
      assert.throws(() => createClient(null), { code: ErrorCode.INVALID_ARGUMENT });
    });

    it('throws NOT_IMPLEMENTED from the scaffolded flow methods', () => {
      const client = createClient(base);
      assert.throws(() => client.createAuthUrl(), { code: ErrorCode.NOT_IMPLEMENTED });
      return assert.rejects(() => client.handleCallback({}), { code: ErrorCode.NOT_IMPLEMENTED });
    });
  });

  describe('createProvider', () => {
    const base = {
      issuer: 'https://auth.example.com',
      jwks: { keys: [] },
      store: {},
    };

    it('accepts a valid config and exposes the handlers', () => {
      const provider = createProvider(base);
      assert.equal(provider.issuer, base.issuer);
      assert.equal(typeof provider.discoveryHandler, 'function');
      assert.equal(typeof provider.userinfoHandler, 'function');
    });

    it('rejects a missing jwks with INVALID_ARGUMENT', () => {
      assert.throws(() => createProvider({ ...base, jwks: undefined }), {
        code: ErrorCode.INVALID_ARGUMENT,
      });
    });

    it('throws NOT_IMPLEMENTED from the scaffolded handlers', () => {
      const provider = createProvider(base);
      assert.throws(() => provider.discoveryHandler(), { code: ErrorCode.NOT_IMPLEMENTED });
      assert.throws(() => provider.userinfoHandler(), { code: ErrorCode.NOT_IMPLEMENTED });
    });
  });
});
