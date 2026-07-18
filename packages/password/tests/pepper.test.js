import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPepper } from '../src/pepper.js';
import { PasswordError, ErrorCode } from '../src/errors.js';

const SECRET = 'sixteen-byte-min-pepper-secret';

test('pepper.wrap is deterministic', () => {
  const p = createPepper({ secret: SECRET });
  assert.equal(p.wrap('same'), p.wrap('same'));
});

test('pepper.wrap changes when the pepper changes', () => {
  const a = createPepper({ secret: SECRET }).wrap('pw');
  const b = createPepper({ secret: 'different-16-byte-secret-here' }).wrap('pw');
  assert.notEqual(a, b);
});

test('pepper.wrap changes when the password changes', () => {
  const p = createPepper({ secret: SECRET });
  assert.notEqual(p.wrap('a'), p.wrap('b'));
});

test('pepper.wrap output is base64 by default, hex when requested', () => {
  const b64 = createPepper({ secret: SECRET }).wrap('pw');
  const hex = createPepper({ secret: SECRET, encoding: 'hex' }).wrap('pw');
  assert.match(b64, /^[A-Za-z0-9+/=]+$/);
  assert.match(hex, /^[0-9a-f]+$/);
});

test('pepper.wrap: sha512 emits longer digest than sha256', () => {
  const short = createPepper({ secret: SECRET, hash: 'sha256', encoding: 'hex' }).wrap('pw').length;
  const long = createPepper({ secret: SECRET, hash: 'sha512', encoding: 'hex' }).wrap('pw').length;
  assert.equal(short, 64);
  assert.equal(long, 128);
});

test('rejects short secrets', () => {
  assert.throws(
    () => createPepper({ secret: 'tiny' }),
    err => err instanceof PasswordError && err.code === ErrorCode.INVALID_ARGUMENT,
  );
});

test('rejects unsupported hash', () => {
  assert.throws(() => createPepper({ secret: SECRET, hash: 'md5' }));
});

// rotation

test('pepper.size reflects number of secrets', () => {
  assert.equal(createPepper({ secret: SECRET }).size, 1);
  assert.equal(createPepper({ secret: [SECRET, 'second-16-byte-secret-here-ok'] }).size, 2);
});

test('pepper.wrap uses the FIRST secret when an array is passed', () => {
  const single = createPepper({ secret: SECRET }).wrap('pw');
  const multi = createPepper({ secret: [SECRET, 'second-16-byte-secret-here-ok'] }).wrap('pw');
  assert.equal(single, multi);
});

test('pepper.wrapAll returns one string per configured secret', () => {
  const p = createPepper({ secret: [SECRET, 'second-16-byte-secret-here-ok'] });
  const all = p.wrapAll('pw');
  assert.equal(all.length, 2);
  assert.notEqual(all[0], all[1]);
});

test('pepper.wrapAll[0] === wrap()', () => {
  const p = createPepper({ secret: [SECRET, 'second-16-byte-secret-here-ok'] });
  assert.equal(p.wrapAll('pw')[0], p.wrap('pw'));
});

test('rotation flow: hash under old, verify walks list, matches under old', async () => {
  const OLD_KEY = 'sixteen-byte-min-pepper-secret';
  const NEW_KEY = 'brand-new-32-byte-pepper-secret!';
  const OLD_ONLY = createPepper({ secret: OLD_KEY });
  const ROTATION = createPepper({ secret: [NEW_KEY, OLD_KEY] });

  // Pretend we minted this hash before rotation
  const scrypt = await import('../src/algorithms/scrypt.js');
  const stored = await scrypt.hash(OLD_ONLY.wrap('userpass'), { N: 1 << 12 });

  // Walk candidates newest-first; the second one (OLD_KEY) should match
  const candidates = ROTATION.wrapAll('userpass');
  let match = -1;
  for (let i = 0; i < candidates.length; i++) {
    if (await scrypt.verify(candidates[i], stored)) {
      match = i;
      break;
    }
  }
  assert.equal(match, 1, 'should match under OLD_KEY (index 1)');
});

test('rejects empty secret array', () => {
  assert.throws(() => createPepper({ secret: [] }));
});

test('rejects too-short secret inside array', () => {
  assert.throws(() => createPepper({ secret: [SECRET, 'tiny'] }));
});
