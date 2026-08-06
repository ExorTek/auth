import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCustomStoreValidator } from '../src/custom-store.js';

const fail = msg => {
  throw new Error(msg);
};

test('throws (via wrap) when impl is not an object', () => {
  const customStore = createCustomStoreValidator({ required: ['get'], wrap: fail });
  assert.throws(() => customStore(null), /requires an object with \{ get \}/);
  assert.throws(() => customStore('nope'), /requires an object/);
});

test('throws (via wrap) when a required method is missing', () => {
  const customStore = createCustomStoreValidator({ required: ['get', 'put'], wrap: fail });
  assert.throws(() => customStore({ get: () => {} }), /impl\.put is required and must be a function/);
});

test('wraps every required method and promotes sync results to Promises', async () => {
  const customStore = createCustomStoreValidator({ required: ['get', 'put'], wrap: fail });
  const store = customStore({
    get: id => `v:${id}`, // sync
    put: async record => record, // async
  });
  const got = store.get('a');
  assert.ok(got instanceof Promise);
  assert.equal(await got, 'v:a');
  assert.deepEqual(await store.put({ id: 1 }), { id: 1 });
});

test('optional methods are wrapped only when present', () => {
  const customStore = createCustomStoreValidator({
    required: ['get'],
    optional: ['extra'],
    wrap: fail,
  });
  assert.equal(typeof customStore({ get: () => {} }).extra, 'undefined');
  assert.equal(typeof customStore({ get: () => {}, extra: () => {} }).extra, 'function');
});

test('coerce post-processes the resolved result', async () => {
  const customStore = createCustomStoreValidator({
    required: ['set'],
    wrap: fail,
    coerce: { set: () => undefined },
  });
  const store = customStore({ set: () => new Map() }); // would leak a Map
  assert.equal(await store.set('k', 'v'), undefined);
});
