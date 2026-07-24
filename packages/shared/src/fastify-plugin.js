import { isFunction, isObject, isString } from './predicates.js';

let counter = 0;

/**
 * Mark a function as a Fastify plugin with encapsulation bypass.
 *
 * Drop-in replacement for the `fastify-plugin` npm package — covers
 * the same symbols and option handling without the external dependency.
 *
 * @param {Function} fn               Plugin function `(fastify, opts) => …`
 * @param {string | PluginOptions} [options]
 *   A semver range string (shorthand for `{ fastify: range }`) or a
 *   full options object.
 * @returns {Function} The same function, decorated with plugin metadata.
 *
 * @typedef {object} PluginOptions
 * @property {string} [name]          Display name. Auto-generated from
 *                                    `fn.name` when omitted.
 * @property {string} [fastify]       Semver range the plugin is compatible
 *                                    with (e.g. `'>=4'`). Fastify checks
 *                                    this at register time.
 * @property {string[]} [decorators]  Decorators the plugin expects to
 *                                    exist before it runs.
 * @property {string[]} [dependencies] Plugins that must be registered
 *                                    before this one.
 * @property {boolean} [encapsulate]  When `true`, the plugin stays
 *                                    encapsulated (skip-override = false).
 *                                    Default `false` (skip override).
 */
export function fastifyPlugin(fn, options) {
  if (fn && fn.default !== undefined) {
    fn = fn.default;
  }

  if (!isFunction(fn)) {
    throw new TypeError(`fastifyPlugin expects a function, instead got '${typeof fn}'`);
  }

  let opts;
  if (isString(options)) {
    opts = { fastify: options };
  } else if (isObject(options)) {
    opts = { ...options };
  } else {
    opts = {};
  }

  if (!opts.name) {
    opts.name = (fn.name || 'anonymous') + '-auto-' + counter++;
  }

  fn[Symbol.for('skip-override')] = opts.encapsulate !== true;
  fn[Symbol.for('fastify.display-name')] = opts.name;
  fn[Symbol.for('plugin-meta')] = opts;

  if (!fn.default) {
    fn.default = fn;
  }

  return fn;
}
