/**
 * Driver matrix for the live-Redis integration suites.
 *
 * `ioredis` and `node-redis` disagree on two call signatures the stores
 * depend on — Lua (`eval(script, numKeys, ...keys, ...args)` vs
 * `eval(script, { keys, arguments })`) and SET-with-TTL
 * (`set(k, v, 'EX', ttl)` vs `set(k, v, { EX: ttl })`). A suite that only
 * ever runs against one driver cannot see a dialect bug in the other, so
 * every integration suite runs against **both**.
 *
 * Usage:
 *
 *   import { forEachRedisDriver } from '@exortek/shared/test-helpers/redis-drivers';
 *
 *   forEachRedisDriver('session store', ({ test, client, ns }) => {
 *     test('put + get round trip', async () => {
 *       const store = redisStore(client(), { keyPrefix: ns('a') });
 *       …
 *     });
 *   });
 *
 * The suite body is invoked once per installed driver. When `REDIS_URL`
 * is unset (a fresh clone with no Docker) a single skipped placeholder
 * test is registered instead, so `yarn test` stays green.
 *
 * Not part of any published bundle — `@exortek/shared` is private, and
 * nothing under `src/` imports this file.
 */

import { test as nodeTest, describe, before, after } from 'node:test';

export const REDIS_URL = process.env.REDIS_URL;

/**
 * @typedef {Object} RedisDriver
 * @property {string} name
 * @property {(url: string) => Promise<any>} connect
 * @property {(client: any) => Promise<void>} quit
 */

/** @type {RedisDriver[]} */
const DRIVERS = [];

try {
  const { default: IoRedis } = await import('ioredis');
  DRIVERS.push({
    name: 'ioredis',
    async connect(url) {
      const client = new IoRedis(url, { lazyConnect: true, maxRetriesPerRequest: 1 });
      await client.connect();
      return client;
    },
    async quit(client) {
      await client.quit();
    },
    raw: {
      get: (c, key) => c.get(key),
      setWithTTL: (c, key, value, ttlMs) => c.set(key, value, 'PX', ttlMs),
      pttl: (c, key) => c.pttl(key),
      sadd: (c, key, ...members) => c.sadd(key, ...members),
      smembers: (c, key) => c.smembers(key),
    },
  });
} catch {
  /* peer not installed — skip this leg of the matrix */
}

try {
  const { createClient } = await import('redis');
  DRIVERS.push({
    name: 'node-redis',
    async connect(url) {
      const client = createClient({ url });
      await client.connect();
      return client;
    },
    async quit(client) {
      await client.quit();
    },
    raw: {
      get: (c, key) => c.get(key),
      setWithTTL: (c, key, value, ttlMs) => c.set(key, value, { PX: ttlMs }),
      pttl: (c, key) => c.pTTL(key),
      sadd: (c, key, ...members) => c.sAdd(key, members),
      smembers: (c, key) => c.sMembers(key),
    },
  });
} catch {
  /* peer not installed — skip this leg of the matrix */
}

/** Driver names available in this process. */
export const driverNames = DRIVERS.map(d => d.name);

/**
 * Run `body` once per installed Redis driver, inside its own `describe`.
 *
 * `body` receives:
 *   - `test`     — node:test's `test`, or a variant carrying `todo` (below)
 *   - `client()` — the connected client, lazily created and auto-quit
 *   - `ns(sfx)`  — a key prefix unique to this run + driver + suffix, so
 *                  parallel runs against one server cannot collide
 *   - `raw`      — driver-agnostic raw commands (`get`, `setWithTTL`, `pttl`,
 *                  `sadd`, `smembers`) for reaching past the store under test
 *   - `driver`   — the driver name, for driver-specific assertions
 *
 * `options.todo` marks this suite's tests as `todo` for the named drivers —
 * used when a known defect is scheduled for a follow-up commit. A failing
 * `todo` test reports its failure in the log but does not fail the run, so
 * the breakage stays visible without blocking a branch-protected merge.
 *
 * @param {string} title
 * @param {(ctx: { test: Function, client: () => any, ns: (suffix?: string) => string, driver: string }) => void} body
 * @param {{ todo?: string | Record<string, string> }} [options]
 */
export function forEachRedisDriver(title, body, options = {}) {
  if (!REDIS_URL) {
    nodeTest(`${title} (skipped — set REDIS_URL to enable)`, { skip: true }, () => {});
    return;
  }
  if (DRIVERS.length === 0) {
    nodeTest(`${title} (skipped — no redis driver installed)`, { skip: true }, () => {});
    return;
  }

  for (const driver of DRIVERS) {
    const todo = resolveTodo(options.todo, driver.name);

    describe(`${title} [${driver.name}]`, () => {
      /** @type {any} */
      let connected = null;
      const client = () => {
        if (!connected) {
          throw new Error('client() called before the suite connected');
        }
        return connected;
      };

      const runNs = `test:${process.pid}:${Date.now()}:${driver.name}:`;
      const ns = (suffix = '') => `${runNs}${suffix}${suffix ? ':' : ''}`;

      // `describe` bodies are collected synchronously, so the connection
      // has to happen in a `before` hook rather than inline.
      before(async () => {
        connected = await driver.connect(REDIS_URL);
      });

      after(async () => {
        if (!connected) {
          return;
        }
        try {
          const keys = await scanKeys(connected, `${runNs}*`);
          if (keys.length) {
            await connected.del(...keys);
          }
        } finally {
          await driver.quit(connected);
          connected = null;
        }
      });

      /**
       * `test(name, fn)` or `test(name, { todo }, fn)`. A per-test `todo`
       * overrides the suite-level one, so a suite can mark only the cases
       * a known defect actually breaks — the rest keep asserting, and so
       * keep catching regressions.
       *
       * @param {string} name
       * @param {{ todo?: string | Record<string, string> } | Function} optionsOrFn
       * @param {Function} [maybeFn]
       */
      const test = (name, optionsOrFn, maybeFn) => {
        const isFn = typeof optionsOrFn === 'function';
        const fn = isFn ? optionsOrFn : maybeFn;
        const opts = isFn ? {} : (optionsOrFn ?? {});
        const reason = resolveTodo('todo' in opts ? opts.todo : todo, driver.name);
        return reason ? nodeTest(name, { todo: reason }, fn) : nodeTest(name, fn);
      };

      // Driver-agnostic raw commands, for suites that need to reach past the
      // store and poke Redis directly (checking a TTL, seeding a stale index
      // entry). Bound to this leg's client so test bodies stay driver-neutral
      // — `raw.sadd(k, m)` rather than `sadd` vs `sAdd`.
      const raw = Object.fromEntries(
        Object.entries(driver.raw).map(([name, fn]) => [name, (...args) => fn(client(), ...args)]),
      );

      body({ test, client, ns, raw, driver: driver.name });
    });
  }
}

/**
 * `todo` may be a plain string (applies to every driver) or a map of
 * driver name → reason (applies only to the named drivers).
 *
 * @param {string | Record<string, string> | undefined} todo
 * @param {string} driverName
 * @returns {string | undefined}
 */
function resolveTodo(todo, driverName) {
  if (!todo) {
    return undefined;
  }
  return typeof todo === 'string' ? todo : todo[driverName];
}

/**
 * `KEYS` is fine for a test namespace but both drivers expose it
 * differently under cluster; scan defensively and fall back.
 *
 * @param {any} client
 * @param {string} pattern
 * @returns {Promise<string[]>}
 */
async function scanKeys(client, pattern) {
  try {
    const keys = await client.keys(pattern);
    return Array.isArray(keys) ? keys : [];
  } catch {
    return [];
  }
}
