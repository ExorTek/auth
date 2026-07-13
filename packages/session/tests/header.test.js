import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractTokenFromHeader } from '../src/header.js';

test('extracts Bearer from lowercased Node header', () => {
  assert.equal(extractTokenFromHeader({ authorization: 'Bearer abc' }), 'abc');
});

test('extracts Bearer from titlecased header (Fastify passthrough)', () => {
  assert.equal(extractTokenFromHeader({ Authorization: 'Bearer abc' }), 'abc');
});

test('extracts from a WHATWG Headers-shaped object', () => {
  const h = new Headers({ Authorization: 'Bearer whatwg' });
  assert.equal(extractTokenFromHeader(h), 'whatwg');
});

test('returns undefined when header missing', () => {
  assert.equal(extractTokenFromHeader({}), undefined);
});

test('returns undefined when prefix mismatched', () => {
  assert.equal(extractTokenFromHeader({ authorization: 'Basic abc' }), undefined);
});

test('returns undefined for empty token after prefix', () => {
  assert.equal(extractTokenFromHeader({ authorization: 'Bearer ' }), undefined);
});

test('honours custom headerName + prefix', () => {
  assert.equal(
    extractTokenFromHeader({ 'x-app-token': 'app_abc' }, { headerName: 'X-App-Token', prefix: 'app_' }),
    'abc',
  );
});

test('array-form headers pick first', () => {
  assert.equal(extractTokenFromHeader({ authorization: ['Bearer first', 'Bearer second'] }), 'first');
});

test('returns undefined for null / undefined input', () => {
  assert.equal(extractTokenFromHeader(null), undefined);
  assert.equal(extractTokenFromHeader(undefined), undefined);
});
