/**
 * Store implementations shipped with `@exortek/opaque`. Any object
 * exposing the {@link OpaqueStore} shape (`set` / `get` / `delete`)
 * works — these are provided as a zero-config default (memory) and a
 * cluster-safe default (Redis).
 */

export { memoryStore } from './memory.js';
export { redisStore } from './redis.js';
export { customStore } from './custom.js';
