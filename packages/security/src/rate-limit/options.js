import { any, duration, number, object } from '@exortek/shared/validate';

import { SecurityError, ErrorCode } from '../internal/errors.js';

const positiveInt = label => number().refine(v => Number.isInteger(v) && v >= 1, `${label} must be a positive integer`);
const positiveNumber = label => number().refine(v => Number.isFinite(v) && v > 0, `${label} must be a positive number`);

const LimiterOptionsSchema = object({
  requests: positiveInt('requests'),
  window: duration(),
  store: any(),
});

const TokenBucketOptionsSchema = object({
  capacity: positiveInt('capacity'),
  refillRate: positiveNumber('refillRate (tokens per second)'),
  store: any(),
});

const LeakyBucketOptionsSchema = object({
  capacity: positiveInt('capacity'),
  leakRate: positiveNumber('leakRate (tokens per second)'),
  store: any(),
});

function parseWith(schema, config, name) {
  try {
    schema.parse(config, `rateLimit.${name}(config)`);
  } catch (err) {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, err instanceof Error ? err.message : String(err));
  }
}

export function assertLimiterOptions(config, name) {
  parseWith(LimiterOptionsSchema, config, name);
  assertStore(config.store, `rateLimit.${name}`);
}

export function assertBucketOptions(config, name) {
  const schema = name === 'tokenBucket' ? TokenBucketOptionsSchema : LeakyBucketOptionsSchema;
  parseWith(schema, config, name);
  assertStore(config.store, `rateLimit.${name}`);
}

export function assertStore(store, ctx) {
  if (!store || typeof store !== 'object') {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `${ctx}: config.store is required — use rateLimit.stores.memory() or an adapter`,
    );
  }
  for (const name of ['get', 'incr', 'set', 'delete']) {
    if (typeof store[name] !== 'function') {
      throw new SecurityError(
        ErrorCode.INVALID_ARGUMENT,
        `${ctx}: config.store is missing '${name}()' — did you pass a raw client instead of an adapter (redisStore(client))?`,
      );
    }
  }
}

export function assertKey(input) {
  if (!input || typeof input !== 'object') {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `limiter.check({ key }): argument must be an object with a "key" field`,
    );
  }
  if (typeof input.key !== 'string' || input.key.length === 0) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `limiter.check({ key }): key must be a non-empty string (e.g. req.ip, "user:123", "apikey:sk_...")`,
    );
  }
}
