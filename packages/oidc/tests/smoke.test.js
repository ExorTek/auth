import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ErrorCode, OidcError, createClient, createProvider } from '../src/index.js';
import { createClient as createClientSub } from '../src/client/index.js';
import { createProvider as createProviderSub } from '../src/provider/index.js';

describe('@exortek/oidc surface', () => {
  it('exposes the public surface from the root barrel', () => {
    assert.equal(typeof createClient, 'function');
    assert.equal(typeof createProvider, 'function');
    assert.equal(typeof OidcError, 'function');
    assert.equal(ErrorCode.INVALID_ARGUMENT, 'INVALID_ARGUMENT');
  });

  it('subpath entries resolve to the same factories', () => {
    assert.equal(createClientSub, createClient);
    assert.equal(createProviderSub, createProvider);
  });
});
