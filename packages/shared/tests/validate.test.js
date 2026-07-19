import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as v from '../src/validate.js';

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

test('int / positiveInt / nonNegativeInt', () => {
  assert.equal(v.int().parse(5, 'x'), 5);
  assert.equal(v.int().safeParse(1.5, 'x').ok, false);
  assert.equal(v.int().safeParse(Number.MAX_SAFE_INTEGER + 1, 'x').ok, false);
  assert.equal(v.int({ min: 2, max: 4 }).safeParse(5, 'x').ok, false);
  assert.equal(v.int({ min: 2, max: 4 }).parse(3, 'x'), 3);

  assert.equal(v.positiveInt().parse(1, 'x'), 1);
  assert.equal(v.positiveInt().safeParse(0, 'x').ok, false);

  assert.equal(v.nonNegativeInt().parse(0, 'x'), 0);
  assert.equal(v.nonNegativeInt().safeParse(-1, 'x').ok, false);
});

test('number / string range options', () => {
  assert.equal(v.number({ min: 0, max: 1 }).parse(0.5, 'x'), 0.5);
  assert.equal(v.number({ min: 0 }).safeParse(-0.1, 'x').ok, false);
  assert.equal(v.number({ max: 10 }).safeParse(11, 'x').ok, false);

  assert.equal(v.string({ minLength: 2 }).parse('ab', 'x'), 'ab');
  assert.equal(v.string({ minLength: 2 }).safeParse('a', 'x').ok, false);
  assert.equal(v.string({ maxLength: 3 }).safeParse('abcd', 'x').ok, false);
});

test('bytes: Buffer / Uint8Array only', () => {
  assert.ok(v.bytes().parse(Buffer.from('hi'), 'x'));
  assert.ok(v.bytes().parse(new Uint8Array(3), 'x'));
  assert.equal(v.bytes().safeParse('hi', 'x').ok, false);
  assert.equal(v.bytes().safeParse(42, 'x').ok, false);
});

test('bytesOrString: also accepts strings', () => {
  assert.equal(v.bytesOrString().parse('secret', 'x'), 'secret');
  assert.ok(v.bytesOrString().parse(Buffer.from('hi'), 'x'));
  assert.equal(v.bytesOrString().safeParse(42, 'x').ok, false);
});

test('func: functions only', () => {
  const fn = () => {};
  assert.equal(v.func().parse(fn, 'x'), fn);
  assert.equal(v.func().safeParse({}, 'x').ok, false);
});

test('literal: exact match via Object.is', () => {
  assert.equal(v.literal('strict').parse('strict', 'x'), 'strict');
  assert.equal(v.literal('strict').safeParse('lax', 'x').ok, false);
  assert.equal(v.literal(NaN).safeParse(NaN, 'x').ok, true);
});

test('record: string-keyed uniform map', () => {
  const s = v.record(v.string());
  const out = s.parse({ a: 'x', b: 'y' }, 'headers');
  assert.equal(out.a, 'x');
  assert.equal(out.b, 'y');

  const bad = s.safeParse({ a: 1 }, 'headers');
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0], /headers\.a/);

  assert.equal(s.safeParse(['x'], 'headers').ok, false);
});

test('record: rejects prototype-polluting keys', () => {
  const s = v.record(v.string());
  const bad = s.safeParse(JSON.parse('{"__proto__": "x"}'), 'h');
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0], /__proto__/);
});

test('withDefault: undefined becomes the default, present values validate', () => {
  const s = v.withDefault(v.positiveInt(), 12);
  assert.equal(s.parse(undefined, 'x'), 12);
  assert.equal(s.parse(3, 'x'), 3);
  assert.equal(s.safeParse(0, 'x').ok, false);
});

test('withDefault composes inside object — schema carries its own defaults', () => {
  const Opts = v.object({
    rounds: v.withDefault(v.positiveInt(), 12),
    mode: v.withDefault(v.oneOf(['prehash', 'strict']), 'prehash'),
  });
  assert.deepEqual(Opts.parse({}, 'options'), { rounds: 12, mode: 'prehash' });
  assert.deepEqual(Opts.parse({ rounds: 10 }, 'options'), { rounds: 10, mode: 'prehash' });
});

test("object unknownKeys: 'reject' fails on typo'd keys, 'strip' stays default", () => {
  const shape = { csrf: v.optional(v.any()), cors: v.optional(v.any()) };

  const strict = v.object(shape, { unknownKeys: 'reject' });
  const bad = strict.safeParse({ csrrf: {} }, 'options');
  assert.equal(bad.ok, false);
  assert.match(bad.errors[0], /unknown key "csrrf"/);
  assert.match(bad.errors[0], /known keys: csrf, cors/);
  assert.equal(strict.safeParse({ csrf: {} }, 'options').ok, true);

  const lax = v.object(shape);
  assert.equal(lax.safeParse({ csrrf: {} }, 'options').ok, true);
});
