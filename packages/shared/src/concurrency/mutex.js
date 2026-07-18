/**
 * Per-key async mutex — a lightweight lock keyed on any string. Every
 * `withLock(key, fn)` call chains onto the previous promise for that
 * key, so callers with the same key execute strictly one after the
 * other. Different keys don't block each other.
 *
 * The map keeps ~one entry per pending caller and cleans up as
 * promises settle, so memory usage is bounded.
 *
 * Only useful for the in-process store. Cross-process serialisation
 * (Redis, other multi-process backends) needs its own atomic primitive
 * (Lua script, WATCH/MULTI, `SET NX`, whatever the client supports).
 */
export function createKeyMutex() {
  /** @type {Map<string, Promise<unknown>>} */
  const chains = new Map();

  return {
    /**
     * @template T
     * @param {string} key
     * @param {() => Promise<T>} fn
     * @returns {Promise<T>}
     */
    async withLock(key, fn) {
      const prior = chains.get(key) ?? Promise.resolve();
      let done;
      const gate = new Promise(resolve => {
        done = resolve;
      });
      chains.set(key, gate);
      try {
        await prior;
        return await fn();
      } finally {
        done();
        if (chains.get(key) === gate) {
          chains.delete(key);
        }
      }
    },
  };
}
