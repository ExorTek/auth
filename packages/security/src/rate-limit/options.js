import { SecurityError, ErrorCode } from '../internal/errors.js';

export function assertLimiterOptions(config, name) {
  if (!config || typeof config !== 'object') {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, `rateLimit.${name}(config) requires an options object`);
  }
  if (!Number.isInteger(config.requests) || config.requests < 1) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `rateLimit.${name}: config.requests must be a positive integer; got ${config.requests}`,
    );
  }
  if (config.window === undefined || config.window === null) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `rateLimit.${name}: config.window is required — pass a duration string like '1m' or an integer of milliseconds`,
    );
  }
  assertStore(config.store, `rateLimit.${name}`);
}

export function assertBucketOptions(config, name) {
  if (!config || typeof config !== 'object') {
    throw new SecurityError(ErrorCode.INVALID_ARGUMENT, `rateLimit.${name}(config) requires an options object`);
  }
  if (!Number.isInteger(config.capacity) || config.capacity < 1) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `rateLimit.${name}: config.capacity must be a positive integer; got ${config.capacity}`,
    );
  }
  const rate = name === 'tokenBucket' ? config.refillRate : config.leakRate;
  const rateField = name === 'tokenBucket' ? 'refillRate' : 'leakRate';
  if (typeof rate !== 'number' || !Number.isFinite(rate) || rate <= 0) {
    throw new SecurityError(
      ErrorCode.INVALID_ARGUMENT,
      `rateLimit.${name}: config.${rateField} must be a positive number (tokens per second); got ${rate}`,
    );
  }
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
