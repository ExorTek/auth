import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generate, passphrase, alphabets } from '../src/generate.js';

test('generate: default length 24', () => {
  const pw = generate();
  assert.equal(pw.length, 24);
});

test('generate: honours length option', () => {
  assert.equal(generate({ length: 8 }).length, 8);
  assert.equal(generate({ length: 128 }).length, 128);
});

test('generate: crockford alphabet excludes 0/O/1/I/L', () => {
  const pw = generate({ length: 200, alphabet: 'crockford' });
  assert.doesNotMatch(pw, /[01OIL]/);
});

test('generate: named alphabet lookup', () => {
  const hex = generate({ length: 32, alphabet: 'hex' });
  assert.match(hex, /^[0-9a-f]{32}$/);
});

test('generate: custom alphabet', () => {
  const pw = generate({ length: 40, alphabet: 'AB' });
  assert.match(pw, /^[AB]{40}$/);
});

test('generate: two calls produce different output', () => {
  assert.notEqual(generate({ length: 24 }), generate({ length: 24 }));
});

test('generate: rough distribution across a small alphabet', () => {
  // With 5000 characters over a 2-symbol alphabet, each should appear
  // within a wide statistical window. Not a rigorous test — just a
  // smoke check that the RNG isn't stuck on one value.
  const pw = generate({ length: 1000, alphabet: 'AB' });
  const a = (pw.match(/A/g) ?? []).length;
  const b = (pw.match(/B/g) ?? []).length;
  assert.ok(a > 400 && a < 600, `A count ${a} outside expected window`);
  assert.ok(b > 400 && b < 600, `B count ${b} outside expected window`);
});

test('generate: rejects invalid length', () => {
  assert.throws(() => generate({ length: 0 }));
  assert.throws(() => generate({ length: 2048 }));
  assert.throws(() => generate({ length: 1.5 }));
});

test('generate: rejects invalid alphabet', () => {
  assert.throws(() => generate({ alphabet: 'x' }));
  assert.throws(() => generate({ alphabet: 42 }));
});

test('alphabets object is frozen', () => {
  assert.ok(Object.isFrozen(alphabets));
});

test('passphrase: default 6 words separated by -', () => {
  const p = passphrase();
  assert.equal(p.split('-').length, 6);
});

test('passphrase: custom separator + words', () => {
  const p = passphrase({ words: 4, separator: ' ' });
  assert.equal(p.split(' ').length, 4);
});

test('passphrase: capitalize flag', () => {
  const p = passphrase({ words: 4, capitalize: true });
  for (const w of p.split('-')) {
    assert.match(w, /^[A-Z]/);
  }
});

test('passphrase: rejects too-small wordlist', () => {
  assert.throws(() => passphrase({ wordList: ['a', 'b', 'c'] }));
});

test('passphrase: two calls produce different output', () => {
  assert.notEqual(passphrase(), passphrase());
});
