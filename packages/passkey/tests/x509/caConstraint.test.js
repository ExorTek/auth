import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { verifyChain } from '../../src/x509/chain.js';

const OPENSSL = 'openssl';
const HAS_OPENSSL = (() => {
  try {
    execSync(`${OPENSSL} version`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

const WORK = join(tmpdir(), 'passkey-ca-constraint-tests');
if (HAS_OPENSSL && !existsSync(WORK)) {
  mkdirSync(WORK, { recursive: true });
}

const sh = cmd => execSync(cmd, { stdio: 'ignore' });
const p = name => join(WORK, name);

/**
 * Build a three-cert chain where the middle certificate is a normal
 * end-entity (basicConstraints CA:FALSE) that nonetheless signs a
 * leaf. RFC 5280 §6.1.4 forbids trusting such a signer; verifyChain
 * must reject it even though every signature is cryptographically
 * valid and the DN linkage is intact.
 */
function buildNonCaIssuerChain() {
  // Root CA (self-signed, CA:TRUE).
  sh(`${OPENSSL} ecparam -name prime256v1 -genkey -noout -out ${p('root.key')}`);
  sh(
    `${OPENSSL} req -x509 -new -key ${p('root.key')} -sha256 -days 3650 -out ${p('root.pem')} ` +
      `-subj "/CN=Test Root CA" -addext "basicConstraints=critical,CA:TRUE"`,
  );

  // "sub" — signed by root but explicitly NOT a CA.
  sh(`${OPENSSL} ecparam -name prime256v1 -genkey -noout -out ${p('sub.key')}`);
  sh(`${OPENSSL} req -new -key ${p('sub.key')} -out ${p('sub.csr')} -subj "/CN=Not A CA"`);
  writeFileSync(p('sub.ext'), 'basicConstraints=critical,CA:FALSE\n');
  sh(
    `${OPENSSL} x509 -req -in ${p('sub.csr')} -CA ${p('root.pem')} -CAkey ${p('root.key')} ` +
      `-CAcreateserial -days 3650 -sha256 -extfile ${p('sub.ext')} -out ${p('sub.pem')}`,
  );

  // Leaf — signed by the non-CA "sub".
  sh(`${OPENSSL} ecparam -name prime256v1 -genkey -noout -out ${p('leaf.key')}`);
  sh(`${OPENSSL} req -new -key ${p('leaf.key')} -out ${p('leaf.csr')} -subj "/CN=Leaf"`);
  sh(
    `${OPENSSL} x509 -req -in ${p('leaf.csr')} -CA ${p('sub.pem')} -CAkey ${p('sub.key')} ` +
      `-CAcreateserial -days 3650 -sha256 -out ${p('leaf.pem')}`,
  );

  return {
    root: readFileSync(p('root.pem'), 'utf8'),
    sub: readFileSync(p('sub.pem'), 'utf8'),
    leaf: readFileSync(p('leaf.pem'), 'utf8'),
  };
}

describe(
  'x509 — issuer basicConstraints CA:TRUE (RFC 5280 §6.1.4)',
  {
    skip: !HAS_OPENSSL ? 'openssl not installed' : false,
  },
  () => {
    test('rejects a chain whose intermediate signer is not a CA', () => {
      const { root, sub, leaf } = buildNonCaIssuerChain();
      assert.throws(
        () => verifyChain({ x5c: [leaf, sub], trustAnchors: [root], now: new Date() }),
        /issuer of certificate 0 is not a CA/,
      );
    });

    test('rejects when a non-CA cert is pinned as the terminating anchor-issuer', () => {
      const { sub, leaf } = buildNonCaIssuerChain();
      // Leaf alone, with the non-CA "sub" pinned as anchor. It issued the
      // leaf (DN + signature match) but must not be trusted to do so.
      assert.throws(
        () => verifyChain({ x5c: [leaf], trustAnchors: [sub], now: new Date() }),
        /issuer of certificate 0 is not a CA/,
      );
    });
  },
);
