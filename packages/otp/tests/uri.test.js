import { test } from 'node:test';
import assert from 'node:assert/strict';
import { provisioningUri, OtpError } from '../src/index.js';

test('provisioningUri: minimal totp', () => {
  const uri = provisioningUri({
    type: 'totp',
    label: 'alice@example.com',
    secret: 'JBSWY3DPEHPK3PXP',
  });
  assert.match(uri, /^otpauth:\/\/totp\//);
  assert.match(uri, /alice%40example\.com/);
  assert.match(uri, /secret=JBSWY3DPEHPK3PXP/);
});

test('provisioningUri: issuer duplicated into label + parameter', () => {
  const uri = provisioningUri({
    label: 'alice@example.com',
    secret: 'JBSWY3DPEHPK3PXP',
    issuer: 'MyApp',
  });
  // Label prefix `MyApp:alice%40example.com`
  assert.match(uri, /MyApp:alice%40example\.com/);
  // Query param
  assert.match(uri, /issuer=MyApp/);
});

test('provisioningUri: only emits non-default params', () => {
  const uri = provisioningUri({
    label: 'a',
    secret: 'JBSWY3DPEHPK3PXP',
  });
  // No algorithm, digits, or period — all defaults.
  assert.doesNotMatch(uri, /algorithm=/);
  assert.doesNotMatch(uri, /digits=/);
  assert.doesNotMatch(uri, /period=/);
});

test('provisioningUri: non-default params get emitted', () => {
  const uri = provisioningUri({
    label: 'a',
    secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA256',
    digits: 8,
    period: 60,
  });
  assert.match(uri, /algorithm=SHA256/);
  assert.match(uri, /digits=8/);
  assert.match(uri, /period=60/);
});

test('provisioningUri: hotp requires counter', () => {
  assert.throws(
    () =>
      provisioningUri({
        type: 'hotp',
        label: 'a',
        secret: 'JBSWY3DPEHPK3PXP',
      }),
    OtpError,
  );
});

test('provisioningUri: hotp emits counter', () => {
  const uri = provisioningUri({
    type: 'hotp',
    label: 'a',
    secret: 'JBSWY3DPEHPK3PXP',
    counter: 5,
  });
  assert.match(uri, /^otpauth:\/\/hotp\//);
  assert.match(uri, /counter=5/);
});

test('provisioningUri: strips padding from secret for scanner compat', () => {
  const uri = provisioningUri({
    label: 'a',
    secret: 'JBSWY3DPEHPK3PXP====',
  });
  assert.doesNotMatch(uri, /secret=[^&]*=/);
});

test('provisioningUri: rejects invalid input', () => {
  assert.throws(() => provisioningUri(null), OtpError);
  assert.throws(() => provisioningUri({ label: '', secret: 's' }), OtpError);
  assert.throws(() => provisioningUri({ label: 'a', secret: '' }), OtpError);
  assert.throws(() => provisioningUri({ type: 'other', label: 'a', secret: 's' }), OtpError);
});

test('provisioningUri: URL-encodes special characters in label + issuer', () => {
  const uri = provisioningUri({
    label: 'a b@c d.com',
    secret: 'JBSWY3DPEHPK3PXP',
    issuer: 'My App / Co',
  });
  // Spaces should be %20, slashes %2F, @ %40.
  assert.match(uri, /My%20App%20%2F%20Co:a%20b%40c%20d\.com/);
});

test('provisioningUri: rejects SHA224/SHA384 as Key URI Format non-standard', () => {
  // Works in hotp/totp for programmatic use — rejected here so nobody
  // renders a QR no Authenticator app will parse.
  assert.throws(
    () =>
      provisioningUri({
        label: 'a',
        secret: 'JBSWY3DPEHPK3PXP',
        algorithm: 'SHA224',
      }),
    /Key URI Format/,
  );
  assert.throws(
    () =>
      provisioningUri({
        label: 'a',
        secret: 'JBSWY3DPEHPK3PXP',
        algorithm: 'SHA384',
      }),
    /Key URI Format/,
  );
});

// parseProvisioningUri — inverse of provisioningUri

import { parseProvisioningUri } from '../src/index.js';

test('parseProvisioningUri: round-trips a minimal totp', () => {
  const uri = provisioningUri({
    label: 'alice@example.com',
    secret: 'JBSWY3DPEHPK3PXP',
    issuer: 'MyApp',
  });
  const info = parseProvisioningUri(uri);
  assert.ok(info);
  assert.equal(info.type, 'totp');
  assert.equal(info.label, 'alice@example.com');
  assert.equal(info.issuer, 'MyApp');
  assert.equal(info.secret, 'JBSWY3DPEHPK3PXP');
});

test('parseProvisioningUri: round-trips a customised totp', () => {
  const uri = provisioningUri({
    label: 'alice@example.com',
    secret: 'JBSWY3DPEHPK3PXP',
    issuer: 'MyApp',
    algorithm: 'SHA256',
    digits: 8,
    period: 60,
  });
  const info = parseProvisioningUri(uri);
  assert.equal(info.algorithm, 'SHA256');
  assert.equal(info.digits, 8);
  assert.equal(info.period, 60);
});

test('parseProvisioningUri: parses hotp with counter', () => {
  const uri = provisioningUri({
    type: 'hotp',
    label: 'alice',
    secret: 'JBSWY3DPEHPK3PXP',
    counter: 42,
  });
  const info = parseProvisioningUri(uri);
  assert.equal(info.type, 'hotp');
  assert.equal(info.counter, 42);
});

test('parseProvisioningUri: rejects hotp URI without a counter', () => {
  // Manually construct a broken hotp URI.
  const info = parseProvisioningUri('otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP');
  assert.equal(info, null);
});

test('parseProvisioningUri: strips whitespace inside secret', () => {
  const info = parseProvisioningUri('otpauth://totp/a?secret=JBSW Y3DP EHPK 3PXP');
  assert.equal(info.secret, 'JBSWY3DPEHPK3PXP');
});

test('parseProvisioningUri: rejects malformed input', () => {
  assert.equal(parseProvisioningUri(null), null);
  assert.equal(parseProvisioningUri(''), null);
  assert.equal(parseProvisioningUri(42), null);
  assert.equal(parseProvisioningUri('https://example.com/'), null);
  assert.equal(parseProvisioningUri('otpauth://other/a?secret=x'), null);
  assert.equal(parseProvisioningUri('otpauth://totp/?secret=x'), null);
  assert.equal(parseProvisioningUri('otpauth://totp/a'), null);
});

test('parseProvisioningUri: label with Issuer: prefix decomposes cleanly', () => {
  const info = parseProvisioningUri('otpauth://totp/Acme:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme');
  assert.equal(info.label, 'alice@example.com');
  assert.equal(info.issuer, 'Acme');
});
