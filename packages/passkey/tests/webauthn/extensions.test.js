import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { base64url } from '@exortek/crypto/encode';
import {
  buildRegistrationExtensions,
  buildAuthenticationExtensions,
  readClientExtensionResults,
  readAuthenticatorExtensions,
} from '../../src/webauthn/extensions.js';

describe('extensions — buildRegistrationExtensions', () => {
  test('empty input yields empty object', () => {
    assert.deepEqual(buildRegistrationExtensions(), {});
  });

  test('credProps must be exactly true', () => {
    assert.deepEqual(buildRegistrationExtensions({ credProps: true }), { credProps: true });
    assert.throws(() => buildRegistrationExtensions({ credProps: false }), /must be `true`/);
  });

  test('largeBlob.support restricted to preferred|required', () => {
    assert.deepEqual(buildRegistrationExtensions({ largeBlob: { support: 'preferred' } }), {
      largeBlob: { support: 'preferred' },
    });
    assert.throws(() => buildRegistrationExtensions({ largeBlob: { support: 'nope' } }), /'preferred' or 'required'/);
  });

  test('prf.eval encodes first/second to base64url', () => {
    const first = new Uint8Array([1, 2, 3]);
    const out = buildRegistrationExtensions({ prf: { eval: { first, second: new Uint8Array([9]) } } });
    assert.equal(out.prf.eval.first, base64url.encode(first));
    assert.equal(out.prf.eval.second, base64url.encode(new Uint8Array([9])));
  });

  test('minPinLength true', () => {
    assert.deepEqual(buildRegistrationExtensions({ minPinLength: true }), { minPinLength: true });
    assert.throws(() => buildRegistrationExtensions({ minPinLength: 8 }), /must be `true`/);
  });

  test('credentialProtectionPolicy 1/2/3 only', () => {
    buildRegistrationExtensions({ credentialProtectionPolicy: 2 });
    assert.throws(() => buildRegistrationExtensions({ credentialProtectionPolicy: 4 }), /CTAP2 §12.1/);
  });

  test('unknown keys pass through', () => {
    const out = buildRegistrationExtensions({ someDraft: { foo: 'bar' } });
    assert.deepEqual(out.someDraft, { foo: 'bar' });
  });

  test('appidExclude type', () => {
    assert.throws(() => buildRegistrationExtensions({ appidExclude: 42 }), /must be a string/);
  });
});

describe('extensions — buildAuthenticationExtensions', () => {
  test('largeBlob read', () => {
    assert.deepEqual(buildAuthenticationExtensions({ largeBlob: { read: true } }), {
      largeBlob: { read: true },
    });
  });

  test('largeBlob write encoded to base64url', () => {
    const write = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const out = buildAuthenticationExtensions({ largeBlob: { write } });
    assert.equal(out.largeBlob.write, base64url.encode(write));
  });

  test('largeBlob read + write mutually exclusive', () => {
    assert.throws(
      () => buildAuthenticationExtensions({ largeBlob: { read: true, write: new Uint8Array(1) } }),
      /mutually exclusive/,
    );
  });

  test('hmacGetSecret requires 32-byte salts', () => {
    buildAuthenticationExtensions({ hmacGetSecret: { salt1: new Uint8Array(32) } });
    assert.throws(() => buildAuthenticationExtensions({ hmacGetSecret: { salt1: new Uint8Array(31) } }), /32-byte/);
    assert.throws(
      () => buildAuthenticationExtensions({ hmacGetSecret: { salt1: new Uint8Array(32), salt2: new Uint8Array(16) } }),
      /salt2 must be a 32-byte/,
    );
  });

  test('prf.evalByCredential preserves keys, encodes values', () => {
    const first = new Uint8Array([1]);
    const out = buildAuthenticationExtensions({
      prf: { evalByCredential: { credA: { first } } },
    });
    assert.equal(out.prf.evalByCredential.credA.first, base64url.encode(first));
  });

  test('appid string', () => {
    const out = buildAuthenticationExtensions({ appid: 'https://legacy.example.com' });
    assert.equal(out.appid, 'https://legacy.example.com');
    assert.throws(() => buildAuthenticationExtensions({ appid: 42 }), /must be a string/);
  });
});

describe('extensions — readClientExtensionResults', () => {
  test('null / undefined → empty', () => {
    assert.deepEqual(readClientExtensionResults(null), {});
    assert.deepEqual(readClientExtensionResults(undefined), {});
  });

  test('non-object rejected', () => {
    assert.throws(() => readClientExtensionResults('nope'), /must be an object/);
    assert.throws(() => readClientExtensionResults([]), /must be an object/);
  });

  test('credProps.rk normalised to boolean', () => {
    const out = readClientExtensionResults({ credProps: { rk: true } });
    assert.deepEqual(out.credProps, { rk: true });
    const out2 = readClientExtensionResults({ credProps: {} });
    assert.deepEqual(out2.credProps, { rk: false });
  });

  test('largeBlob.blob decoded from base64url', () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const out = readClientExtensionResults({ largeBlob: { blob: base64url.encode(bytes) } });
    assert.deepEqual(out.largeBlob.blob, bytes);
  });

  test('largeBlob.blob invalid base64url throws', () => {
    assert.throws(() => readClientExtensionResults({ largeBlob: { blob: '￿*not*base64*' } }), /not valid base64url/);
  });

  test('largeBlob.supported / written flags', () => {
    const out = readClientExtensionResults({ largeBlob: { supported: true, written: true } });
    assert.equal(out.largeBlob.supported, true);
    assert.equal(out.largeBlob.written, true);
  });

  test('prf.results.first + second decoded', () => {
    const first = new Uint8Array([1, 2]);
    const second = new Uint8Array([3, 4]);
    const out = readClientExtensionResults({
      prf: { enabled: true, results: { first: base64url.encode(first), second: base64url.encode(second) } },
    });
    assert.equal(out.prf.enabled, true);
    assert.deepEqual(out.prf.results.first, first);
    assert.deepEqual(out.prf.results.second, second);
  });

  test('appid / appidExclude booleans surface', () => {
    const out = readClientExtensionResults({ appid: true, appidExclude: false });
    assert.equal(out.appid, true);
    assert.equal(out.appidExclude, false);
  });

  test('unknown keys surfaced under `raw`', () => {
    const out = readClientExtensionResults({ credProps: { rk: true }, someDraft: { x: 1 } });
    assert.deepEqual(out.raw.someDraft, { x: 1 });
  });
});

describe('extensions — readAuthenticatorExtensions', () => {
  test('null / undefined → empty', () => {
    assert.deepEqual(readAuthenticatorExtensions(null), {});
    assert.deepEqual(readAuthenticatorExtensions(undefined), {});
  });

  test('non-Map rejected', () => {
    assert.throws(() => readAuthenticatorExtensions({}), /must be a Map/);
  });

  test('hmac-secret bytes surfaced as hmacSecret', () => {
    const bytes = new Uint8Array(32).fill(0xab);
    const out = readAuthenticatorExtensions(new Map([['hmac-secret', bytes]]));
    assert.deepEqual(out.hmacSecret, bytes);
  });

  test('hmac-secret === true (registration confirmation) surfaced', () => {
    const out = readAuthenticatorExtensions(new Map([['hmac-secret', true]]));
    assert.equal(out.hmacSecret, true);
  });

  test('minPinLength surfaced', () => {
    const out = readAuthenticatorExtensions(new Map([['minPinLength', 6]]));
    assert.equal(out.minPinLength, 6);
  });

  test('minPinLength ignored when non-integer', () => {
    const out = readAuthenticatorExtensions(new Map([['minPinLength', 'six']]));
    assert.equal(out.minPinLength, undefined);
  });

  test('credProtect surfaced when 1/2/3', () => {
    const out = readAuthenticatorExtensions(new Map([['credProtect', 2]]));
    assert.equal(out.credProtect, 2);
  });

  test('raw carries every entry', () => {
    const out = readAuthenticatorExtensions(
      new Map([
        ['minPinLength', 4],
        ['x-draft', 'y'],
      ]),
    );
    assert.equal(out.raw.minPinLength, 4);
    assert.equal(out.raw['x-draft'], 'y');
  });
});
