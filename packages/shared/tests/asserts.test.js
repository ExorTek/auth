import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import { bindAsserts } from '../src/asserts.js';
import { object, string, number, optional } from '../src/validate.js';

class FakePackageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FakePackageError';
    this.code = 'INVALID_ARGUMENT';
  }
}

const g = bindAsserts(m => new FakePackageError(m));

describe('bindAsserts — error identity', () => {
  test('failures throw the bound class, not plain Error', () => {
    try {
      g.assertPositiveInt(-1, 'x');
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(err instanceof FakePackageError);
      assert.equal(err.code, 'INVALID_ARGUMENT');
    }
  });

  test('two bindings are independent', () => {
    class OtherError extends Error {}
    const other = bindAsserts(m => new OtherError(m));
    assert.throws(() => other.assertString(42, 'x'), OtherError);
    assert.throws(() => g.assertString(42, 'x'), FakePackageError);
  });

  test('invalidArgument constructs (not throws) the bound error', () => {
    const err = g.invalidArgument('free-form message');
    assert.ok(err instanceof FakePackageError);
    assert.equal(err.message, 'free-form message');
  });
});

describe('bindAsserts — hint option', () => {
  test('hint is appended after an em-dash', () => {
    assert.throws(
      () => g.assertBytes('not bytes', 'ciphertext', { hint: 'pass the exact bytes returned by encrypt()' }),
      /ciphertext must be a Buffer or Uint8Array — pass the exact bytes returned by encrypt\(\)/,
    );
  });

  test('no hint → plain message', () => {
    assert.throws(() => g.assertBytes('not bytes', 'x'), /^FakePackageError: x must be a Buffer or Uint8Array$/);
  });
});

describe('parse — validate bridge', () => {
  const Schema = object({ name: string(), size: optional(number()) });

  test('valid input returns the parsed value', () => {
    const out = g.parse(Schema, { name: 'a', size: 3 });
    assert.deepEqual(out, { name: 'a', size: 3 });
  });

  test('invalid input throws the bound class with every collected message', () => {
    try {
      g.parse(Schema, { name: 42, size: 'big' }, 'options');
      assert.fail('should have thrown');
    } catch (err) {
      assert.ok(err instanceof FakePackageError);
      assert.match(err.message, /options\.name/);
      assert.match(err.message, /options\.size/);
    }
  });

  test('default path is "options"', () => {
    assert.throws(() => g.parse(Schema, null), /options: expected object/);
  });
});

describe('assertPositiveInt', () => {
  test('accepts positive integers', () => {
    for (const v of [1, 2, 100, Number.MAX_SAFE_INTEGER]) {
      assert.doesNotThrow(() => g.assertPositiveInt(v, 'x'));
    }
  });

  test('rejects zero, negatives, floats, unsafe, non-numbers', () => {
    for (const v of [0, -1, 1.5, 'nope', null, undefined, Number.MAX_SAFE_INTEGER + 1, NaN]) {
      assert.throws(() => g.assertPositiveInt(v, 'x'));
    }
  });

  test('error message includes the argument name', () => {
    assert.throws(
      () => g.assertPositiveInt(-1, 'options.iterations'),
      /options\.iterations must be a positive integer/,
    );
  });
});

describe('assertNonNegativeInt', () => {
  test('accepts 0 and positive', () => {
    for (const v of [0, 1, 100]) assert.doesNotThrow(() => g.assertNonNegativeInt(v, 'x'));
  });

  test('rejects negative + non-int', () => {
    for (const v of [-1, 1.5, NaN, 'x']) assert.throws(() => g.assertNonNegativeInt(v, 'x'));
  });
});

describe('assertUint48', () => {
  test('accepts 0..2^48-1', () => {
    assert.doesNotThrow(() => g.assertUint48(0, 'ms'));
    assert.doesNotThrow(() => g.assertUint48(0xffffffffffff, 'ms'));
  });

  test('rejects out-of-range', () => {
    assert.throws(() => g.assertUint48(-1, 'ms'));
    assert.throws(() => g.assertUint48(0x1000000000000, 'ms'));
  });
});

describe('assertString / assertNonEmptyString', () => {
  test('assertString accepts strings incl. empty', () => {
    assert.doesNotThrow(() => g.assertString('', 'x'));
    assert.doesNotThrow(() => g.assertString('hi', 'x'));
  });

  test('assertString rejects non-strings', () => {
    for (const v of [42, null, undefined, {}, []]) {
      assert.throws(() => g.assertString(v, 'x'));
    }
  });

  test('assertNonEmptyString rejects empty string and non-strings', () => {
    assert.doesNotThrow(() => g.assertNonEmptyString('hi', 'x'));
    for (const v of ['', 42, null, undefined]) {
      assert.throws(() => g.assertNonEmptyString(v, 'x'), /x must be a non-empty string/);
    }
  });
});

describe('assertBoolean / assertFunction', () => {
  test('assertBoolean accepts booleans only', () => {
    assert.doesNotThrow(() => g.assertBoolean(true, 'x'));
    assert.doesNotThrow(() => g.assertBoolean(false, 'x'));
    for (const v of [0, 1, 'true', null, undefined]) {
      assert.throws(() => g.assertBoolean(v, 'x'));
    }
  });

  test('assertFunction accepts functions only', () => {
    assert.doesNotThrow(() => g.assertFunction(() => {}, 'x'));
    assert.doesNotThrow(() => g.assertFunction(async () => {}, 'x'));
    for (const v of [{}, 'fn', null, undefined]) {
      assert.throws(() => g.assertFunction(v, 'x'), /x must be a function/);
    }
  });
});

describe('assertObject / assertOptionalObject', () => {
  test('accepts plain objects; rejects null, arrays, primitives', () => {
    assert.doesNotThrow(() => g.assertObject({}, 'x'));
    assert.throws(() => g.assertObject(null, 'x'));
    assert.throws(() => g.assertObject([], 'x'));
    assert.throws(() => g.assertObject(42, 'x'));
  });

  test('optional variant skips undefined', () => {
    assert.doesNotThrow(() => g.assertOptionalObject(undefined, 'x'));
    assert.throws(() => g.assertOptionalObject(null, 'x'));
  });
});

describe('assertBytes / assertBytesOrString', () => {
  test('assertBytes accepts Buffer / Uint8Array only — no strings', () => {
    assert.doesNotThrow(() => g.assertBytes(Buffer.from('hi'), 'x'));
    assert.doesNotThrow(() => g.assertBytes(new Uint8Array(3), 'x'));
    for (const v of ['hi', 42, {}, null]) {
      assert.throws(() => g.assertBytes(v, 'x'), /x must be a Buffer or Uint8Array/);
    }
  });

  test('assertBytesOrString accepts string / Buffer / Uint8Array', () => {
    assert.doesNotThrow(() => g.assertBytesOrString('hi', 'x'));
    assert.doesNotThrow(() => g.assertBytesOrString(Buffer.from('hi'), 'x'));
    assert.doesNotThrow(() => g.assertBytesOrString(new Uint8Array(3), 'x'));
  });

  test('assertBytesOrString rejects other', () => {
    assert.throws(() => g.assertBytesOrString(42, 'x'));
    assert.throws(() => g.assertBytesOrString({}, 'x'));
    assert.throws(() => g.assertBytesOrString(null, 'x'));
  });
});

describe('assertEncoding', () => {
  test('default allows buffer', () => {
    for (const e of ['hex', 'base64', 'base64url', 'buffer']) {
      assert.doesNotThrow(() => g.assertEncoding(e, 'enc'));
    }
  });

  test('allowBuffer: false rejects buffer', () => {
    assert.throws(() => g.assertEncoding('buffer', 'enc', { allowBuffer: false }));
    assert.doesNotThrow(() => g.assertEncoding('hex', 'enc', { allowBuffer: false }));
  });

  test('rejects unknown encoding', () => {
    assert.throws(() => g.assertEncoding('utf8', 'enc'));
    assert.throws(() => g.assertEncoding(42, 'enc'));
  });
});
