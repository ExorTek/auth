import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as bcrypt from '../src/algorithms/bcrypt.js';
import { preparePasswordForBcrypt } from '../src/algorithms/bcrypt.js';
import { PasswordError, ErrorCode } from '../src/errors.js';

let available = false;
try {
  await import('bcryptjs');
  available = true;
} catch {
  /* peer not installed */
}

// bcrypt rounds=4 is the minimum accepted by bcryptjs; keep tests fast.
const FAST = { rounds: 4 };

test('bcrypt.hash returns $2b$-shaped string', { skip: !available && 'bcryptjs not installed' }, async () => {
  const s = await bcrypt.hash('pw', FAST);
  assert.match(s, /^\$2[abxy]?\$04\$/);
});

test('bcrypt round-trip verify', { skip: !available && 'bcryptjs not installed' }, async () => {
  const s = await bcrypt.hash('secret', FAST);
  assert.equal(await bcrypt.verify('secret', s), true);
  assert.equal(await bcrypt.verify('other', s), false);
});

test('bcrypt.verify: wrong-algo hash → false', { skip: !available && 'bcryptjs not installed' }, async () => {
  assert.equal(await bcrypt.verify('anything', '$scrypt$ln=17,r=8,p=1$c2FsdA$aGFzaA'), false);
  assert.equal(await bcrypt.verify('anything', 'not-a-hash'), false);
});

test(
  'bcrypt 72-byte gotcha: prehash mode makes every byte count',
  { skip: !available && 'bcryptjs not installed' },
  async () => {
    const short = 'A'.repeat(80);
    const shortPlusOne = 'A'.repeat(80) + 'B';
    const h1 = await bcrypt.hash(short, FAST);
    // Different-suffix inputs must NOT verify against the same stored hash
    // when prehash is on — proves suffix bytes influenced the KDF.
    assert.equal(await bcrypt.verify(shortPlusOne, h1), false);
    assert.equal(await bcrypt.verify(short, h1), true);
  },
);

test('bcrypt strict mode: refuses > 72-byte input', async () => {
  const big = 'A'.repeat(80);
  const bytes = Buffer.from(big, 'utf8');
  assert.throws(
    () => preparePasswordForBcrypt(bytes, 'strict'),
    err => err instanceof PasswordError && err.code === ErrorCode.PASSWORD_TOO_LONG,
  );
});

test('bcrypt truncate mode: matches historical silent-truncate behaviour', () => {
  const big = 'A'.repeat(100);
  const truncated = preparePasswordForBcrypt(Buffer.from(big, 'utf8'), 'truncate');
  assert.equal(truncated.length, 72);
  assert.equal(truncated.toString('utf8'), 'A'.repeat(72));
});

test('bcrypt.needsRehash: rounds < target → true', { skip: !available && 'bcryptjs not installed' }, async () => {
  const s = await bcrypt.hash('pw', FAST);
  assert.equal(bcrypt.needsRehash(s, { rounds: 12 }), true);
});

test('bcrypt.needsRehash: rounds >= target → false', { skip: !available && 'bcryptjs not installed' }, async () => {
  const s = await bcrypt.hash('pw', { rounds: 12 });
  assert.equal(bcrypt.needsRehash(s, { rounds: 12 }), false);
});

test('bcrypt.needsRehash: unrecognised → true', () => {
  assert.equal(bcrypt.needsRehash(''), true);
  assert.equal(bcrypt.needsRehash('$scrypt$ln=17,r=8,p=1$c2FsdA$aGFzaA'), true);
});

test('bcrypt.hash: invalid rounds rejected', async () => {
  await assert.rejects(bcrypt.hash('pw', { rounds: 2 }));
  await assert.rejects(bcrypt.hash('pw', { rounds: 40 }));
});
