import { test } from 'node:test';
import assert from 'node:assert/strict';
import { enroll, parseProvisioningUri, verifyBackupCode, totp, verifyTotp, OtpError } from '../src/index.js';

test('enroll: bundles secret + uri + backupCodes for the default TOTP flow', () => {
  const bundle = enroll({ label: 'alice@example.com', issuer: 'MyApp' });
  assert.ok(bundle.secret.length > 0);
  assert.match(bundle.uri, /^otpauth:\/\/totp\//);
  assert.equal(bundle.backupCodes.length, 10);

  // The URI should round-trip cleanly.
  const info = parseProvisioningUri(bundle.uri);
  assert.equal(info.secret, bundle.secret);
  assert.equal(info.label, 'alice@example.com');
  assert.equal(info.issuer, 'MyApp');
});

test('enroll: current TOTP verifies against the minted secret', async () => {
  const bundle = enroll({ label: 'alice@example.com' });
  const code = totp(bundle.secret);
  assert.equal(await verifyTotp(code, bundle.secret), true);
});

test('enroll: honors backupCodeCount: 0', () => {
  const bundle = enroll({ label: 'alice@example.com', backupCodeCount: 0 });
  assert.equal(bundle.backupCodes.length, 0);
});

test('enroll: threads secretOptions through to generateSecret', () => {
  const bundle = enroll({
    label: 'alice',
    secretOptions: { bytes: 32, encoding: 'hex' },
  });
  // 32 bytes hex = 64 chars.
  assert.equal(bundle.secret.length, 64);
});

test('enroll: hotp variant emits counter', () => {
  const bundle = enroll({
    label: 'alice',
    type: 'hotp',
    counter: 7,
  });
  const info = parseProvisioningUri(bundle.uri);
  assert.equal(info.type, 'hotp');
  assert.equal(info.counter, 7);
});

test('enroll: rejects missing label', () => {
  assert.throws(() => enroll({}), OtpError);
  assert.throws(() => enroll({ label: '' }), OtpError);
  assert.throws(() => enroll(null), OtpError);
});

// verifyBackupCode

test('verifyBackupCode: returns the matching index', () => {
  const codes = ['A3F4-9K2M', 'X7QP-5NB2', 'Y8RS-1TV6'];
  assert.equal(verifyBackupCode('X7QP-5NB2', codes), 1);
  assert.equal(verifyBackupCode('x7qp5nb2', codes), 1); // case + no dash
  assert.equal(verifyBackupCode(' A3F4 9K2M ', codes), 0); // spaces
});

test('verifyBackupCode: returns null on no match', () => {
  const codes = ['A3F4-9K2M', 'X7QP-5NB2'];
  assert.equal(verifyBackupCode('WRONG-CODE', codes), null);
  assert.equal(verifyBackupCode('', codes), null);
  assert.equal(verifyBackupCode(null, codes), null);
});

test('verifyBackupCode: handles empty / invalid list', () => {
  assert.equal(verifyBackupCode('X7QP-5NB2', []), null);
  assert.equal(verifyBackupCode('X7QP-5NB2', null), null);
});
