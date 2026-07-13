import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseHash, serialiseHash } from '../src/phc.js';

test('parseHash returns null for non-strings', () => {
  assert.equal(parseHash(null), null);
  assert.equal(parseHash(''), null);
  assert.equal(parseHash(42), null);
  assert.equal(parseHash('plain-text-not-phc'), null);
});

test('parseHash: scrypt PHC round-trip', () => {
  const salt = Buffer.from('sixteen-byte-salt', 'utf8');
  const hash = Buffer.from('thirty-two-byte-hash-of-a-secret', 'utf8');
  const s = serialiseHash({
    algorithm: 'scrypt',
    params: { ln: 17, r: 8, p: 1 },
    salt,
    hash,
  });
  assert.match(s, /^\$scrypt\$ln=17,r=8,p=1\$.+\$.+$/);
  const parsed = parseHash(s);
  assert.equal(parsed.algorithm, 'scrypt');
  assert.equal(parsed.params.ln, 17);
  assert.equal(parsed.params.r, 8);
  assert.equal(parsed.params.p, 1);
  assert.deepEqual(parsed.salt, salt);
  assert.deepEqual(parsed.hash, hash);
});

test('parseHash: argon2id with version segment', () => {
  const s = serialiseHash({
    algorithm: 'argon2id',
    params: { v: 19, m: 19456, t: 2, p: 1 },
    salt: Buffer.from('salt1234salt1234', 'utf8'),
    hash: Buffer.from('hash5678hash5678hash5678hash5678', 'utf8'),
  });
  assert.match(s, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
  const parsed = parseHash(s);
  assert.equal(parsed.algorithm, 'argon2id');
  assert.equal(parsed.params.v, 19);
  assert.equal(parsed.params.m, 19456);
});

test('parseHash: pbkdf2-sha256', () => {
  const s = serialiseHash({
    algorithm: 'pbkdf2-sha256',
    params: { i: 600000 },
    salt: Buffer.from('salt1234salt1234', 'utf8'),
    hash: Buffer.from('hash5678hash5678hash5678hash5678', 'utf8'),
  });
  const parsed = parseHash(s);
  assert.equal(parsed.algorithm, 'pbkdf2-sha256');
  assert.equal(parsed.params.i, 600000);
});

test('parseHash: bcrypt native format', () => {
  const example = '$2b$12$eImiTXuWVxfM37uY4JANjQvOePUAgeGRXcpB8HzY6xtOCoQmSvzCq';
  const parsed = parseHash(example);
  assert.equal(parsed.algorithm, 'bcrypt');
  assert.equal(parsed.params.rounds, 12);
  assert.equal(parsed.salt, null);
  assert.equal(parsed.hash, null);
  assert.equal(parsed.raw, example);
});

test('parseHash: bcrypt variants 2a / 2b / 2y', () => {
  for (const variant of ['2a', '2b', '2y']) {
    const s = `$${variant}$10$eImiTXuWVxfM37uY4JANjQvOePUAgeGRXcpB8HzY6xtOCoQmSvzCq`;
    const parsed = parseHash(s);
    assert.equal(parsed?.algorithm, 'bcrypt', `variant ${variant} should parse`);
    assert.equal(parsed?.params.rounds, 10);
  }
});

test('parseHash rejects malformed inputs', () => {
  assert.equal(parseHash('$notreal$'), null);
  assert.equal(parseHash('$scrypt$'), null);
  assert.equal(parseHash('$scrypt$ln=17$$'), null);
  assert.equal(parseHash('$2b$99$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'), null);
});

test('serialiseHash refuses bcrypt (non-PHC format)', () => {
  assert.throws(() =>
    serialiseHash({
      algorithm: 'bcrypt',
      params: { rounds: 12 },
      salt: Buffer.alloc(16),
      hash: Buffer.alloc(23),
    }),
  );
});
