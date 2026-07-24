import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fastifyPlugin } from '../src/fastify-plugin.js';

describe('fastifyPlugin', () => {
  it('sets skip-override and display-name', () => {
    async function myPlugin() {}
    const result = fastifyPlugin(myPlugin, { name: 'test-plugin' });
    assert.equal(result, myPlugin);
    assert.equal(result[Symbol.for('skip-override')], true);
    assert.equal(result[Symbol.for('fastify.display-name')], 'test-plugin');
  });

  it('stores plugin-meta with all options', () => {
    async function myPlugin() {}
    const opts = { name: 'p', fastify: '>=4', decorators: ['db'], dependencies: ['auth'] };
    fastifyPlugin(myPlugin, opts);
    const meta = myPlugin[Symbol.for('plugin-meta')];
    assert.equal(meta.name, 'p');
    assert.equal(meta.fastify, '>=4');
    assert.deepEqual(meta.decorators, ['db']);
    assert.deepEqual(meta.dependencies, ['auth']);
  });

  it('accepts a version string as shorthand', () => {
    async function myPlugin() {}
    fastifyPlugin(myPlugin, '>=4');
    assert.equal(myPlugin[Symbol.for('plugin-meta')].fastify, '>=4');
  });

  it('auto-generates name from fn.name when omitted', () => {
    async function coolPlugin() {}
    fastifyPlugin(coolPlugin);
    const name = coolPlugin[Symbol.for('fastify.display-name')];
    assert.ok(name.startsWith('coolPlugin-auto-'));
  });

  it('auto-generates name for anonymous functions', () => {
    const fn = async () => {};
    fastifyPlugin(fn);
    const name = fn[Symbol.for('fastify.display-name')];
    assert.ok(name.startsWith('anonymous-auto-') || name.startsWith('fn-auto-'));
  });

  it('encapsulate: true disables skip-override', () => {
    async function myPlugin() {}
    fastifyPlugin(myPlugin, { name: 'enc', encapsulate: true });
    assert.equal(myPlugin[Symbol.for('skip-override')], false);
  });

  it('sets fn.default for faux module support', () => {
    async function myPlugin() {}
    fastifyPlugin(myPlugin, { name: 'faux' });
    assert.equal(myPlugin.default, myPlugin);
  });

  it('handles export-default style input', () => {
    async function realPlugin() {}
    const mod = { default: realPlugin };
    const result = fastifyPlugin(mod, { name: 'esm' });
    assert.equal(result, realPlugin);
    assert.equal(realPlugin[Symbol.for('skip-override')], true);
  });

  it('throws on non-function input', () => {
    assert.throws(() => fastifyPlugin('not a fn'), /expects a function/);
    assert.throws(() => fastifyPlugin(42), /expects a function/);
    assert.throws(() => fastifyPlugin(null), /expects a function/);
  });

  it('works with no options', () => {
    async function bare() {}
    const result = fastifyPlugin(bare);
    assert.equal(result, bare);
    assert.equal(result[Symbol.for('skip-override')], true);
    assert.ok(result[Symbol.for('fastify.display-name')]);
  });
});
