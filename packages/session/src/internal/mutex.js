/**
 * Per-key async mutex — a lightweight lock keyed on any string. Every
 * `withLock(key, fn)` call chains onto the previous promise for that
 * key, so callers with the same key execute strictly one after the
 * other. Different keys don't block each other.
 *
 * The map keeps ~one entry per pending caller and cleans up as
 * promises settle, so memory usage is bounded.
 *
 * Only useful for the memory store — Redis / other multi-process
 * stores need their own atomic primitive (Lua script, WATCH/MULTI,
 * ZADD NX, whatever the client supports).
 */
export function createKeyMutex() {
  /** @type {Map<string, Promise<any>>} */
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
      // Publish the gate before awaiting `prior` — parallel callers
      // grab this same gate and chain onto it.
      chains.set(key, gate);
      try {
        await prior;
        return await fn();
      } finally {
        done();
        // If we're still the tail of the chain, drop the entry. Under
        // continued contention someone else has already replaced us
        // and this delete is a no-op — hence the identity check.
        if (chains.get(key) === gate) {
          chains.delete(key);
        }
      }
    },
  };
}
