import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as v from '../src/validate/schema.js';

test('string: passes strings, rejects others with path', () => {
  const s = v.string();
  assert.equal(s.parse('hi', 'x'), 'hi');
  const bad = s.safeParse(42, 'x');
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0], /x: expected string/);
});

test('number: rejects NaN + Infinity', () => {
  const n = v.number();
  assert.equal(n.parse(3.14), 3.14);
  assert.equal(n.safeParse(NaN).ok, false);
  assert.equal(n.safeParse(Infinity).ok, false);
});

test('boolean: strict', () => {
  const b = v.boolean();
  assert.equal(b.parse(true), true);
  assert.equal(b.safeParse('true').ok, false);
});

test('oneOf: string enum', () => {
  const alg = v.oneOf(['HS256', 'RS256']);
  assert.equal(alg.parse('HS256'), 'HS256');
  const bad = alg.safeParse('none', 'options.alg');
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0], /expected one of/);
});

test('object: aggregates nested errors', () => {
  const s = v.object({
    alg: v.string(),
    expiresIn: v.number(),
  });
  const good = s.parse({ alg: 'HS256', expiresIn: 900 }, 'options');
  assert.deepEqual(good, { alg: 'HS256', expiresIn: 900 });

  const bad = s.safeParse({ alg: 42, expiresIn: 'nope' }, 'options');
  assert.equal(bad.ok, false);
  assert.equal(bad.errors.length, 2);
  assert.match(bad.errors[0], /options\.alg/);
  assert.match(bad.errors[1], /options\.expiresIn/);
});

test('array: propagates per-element path', () => {
  const s = v.array(v.string());
  const bad = s.safeParse(['a', 2, 'c'], 'audience');
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0], /audience\[1\]/);
});

test('union: matches the first passing branch', () => {
  const s = v.union(v.number(), v.string());
  assert.equal(s.parse(5), 5);
  assert.equal(s.parse('abc'), 'abc');
  assert.equal(s.safeParse(true).ok, false);
});

test('optional: skips undefined, still validates present', () => {
  const s = v.optional(v.string());
  assert.equal(s.parse(undefined), undefined);
  assert.equal(s.parse('x'), 'x');
  assert.equal(s.safeParse(42).ok, false);
});

test('nullable: allows null', () => {
  const s = v.nullable(v.string());
  assert.equal(s.parse(null), null);
  assert.equal(s.parse('x'), 'x');
});

test('custom: predicate with message', () => {
  const s = v.custom(x => x > 0, 'must be positive');
  assert.equal(s.parse(3), 3);
  const bad = s.safeParse(-1, 'n');
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0], /n: must be positive/);
});

test('refine: chains a constraint on top of a base schema', () => {
  const evenNumber = v.number().refine(n => n % 2 === 0, 'must be even');
  assert.equal(evenNumber.parse(4), 4);
  const bad = evenNumber.safeParse(3, 'n');
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0], /must be even/);
});

test('duration: accepts number or duration string', () => {
  const s = v.duration();
  assert.equal(s.parse(900), 900);
  assert.equal(s.parse('15m'), '15m');
  assert.equal(s.parse('500ms'), '500ms');
  assert.equal(s.safeParse('nope').ok, false);
});

test('regexp: accepts RegExp instances', () => {
  const s = v.regexp();
  assert.ok(s.parse(/abc/));
  assert.equal(s.safeParse('abc').ok, false);
});

test('nested composition — a realistic config schema', () => {
  const OpenApiOpts = v.object({
    alg: v.oneOf(['HS256', 'RS256', 'ES256']),
    expiresIn: v.optional(v.duration()),
    audience: v.optional(v.union(v.string(), v.regexp(), v.array(v.union(v.string(), v.regexp())))),
    store: v.optional(v.custom(x => x && typeof x.add === 'function', 'must be a Store')),
  });

  const good = OpenApiOpts.parse(
    {
      alg: 'RS256',
      expiresIn: '2h',
      audience: [/^api\./, 'api.myapp.com'],
      store: { add: () => {} },
    },
    'options',
  );
  assert.equal(good.alg, 'RS256');
  assert.equal(good.expiresIn, '2h');

  const bad = OpenApiOpts.safeParse({ alg: 'none' }, 'options');
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0], /options\.alg/);
});
