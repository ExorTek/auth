import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { hasSubjectAttribute, parseSubject } from '../../src/x509/subject.js';

describe('x509 subject — exact attribute matching', () => {
  test('an escaped comma inside a value is not a separate attribute', () => {
    const subject = 'CN=evil\\,CN=attest.android.com\nO=Evil OU=Authenticator Attestation';
    assert.deepEqual(parseSubject(subject), [
      ['CN', 'evil,CN=attest.android.com'],
      ['O', 'Evil OU=Authenticator Attestation'],
    ]);
    assert.equal(hasSubjectAttribute(subject, 'CN', 'attest.android.com'), false);
    assert.equal(hasSubjectAttribute(subject, 'OU', 'Authenticator Attestation'), false);
  });

  test('matches the real attribute', () => {
    const subject = 'C=US\nO=Vendor\nOU=Authenticator Attestation\nCN=Vendor Key';
    assert.equal(hasSubjectAttribute(subject, 'OU', 'Authenticator Attestation'), true);
    assert.equal(hasSubjectAttribute('CN=Attest.Android.com', 'cn', 'attest.android.com', { ignoreCase: true }), true);
  });
});
