/**
 * A single-use `jti` replay cache with O(1) amortised eviction. Both the
 * DPoP proof cache (RFC 9449) and the client-assertion cache (RFC 7523)
 * need the same thing: remember an id for a short window, reject a repeat,
 * and never grow without bound.
 *
 * A naive one-map cache with a "sweep the whole map when it gets big"
 * policy is O(n) on every call past the threshold. Instead we keep two
 * buckets and rotate: writes land in the live bucket; a lookup checks
 * both; once a full retention window passes the stale bucket is dropped
 * whole (every id in it has necessarily expired) and a fresh one takes
 * its place. Eviction is a single map swap, not a scan.
 *
 * Module-level and single-process by design — a multi-node deployment
 * that needs cross-node replay defence supplies a shared store instead.
 */

/**
 * @param {number} retentionMs   how long an id stays remembered
 * @returns {{ seen: (id: string) => boolean, size: () => number, clear: () => void }}
 */
export function createReplayCache(retentionMs) {
  /** @type {Map<string, true>} */
  let live = new Map();
  /** @type {Map<string, true>} */
  let prev = new Map();
  let rotatedAt = Date.now();

  function rotateIfDue() {
    if (Date.now() - rotatedAt >= retentionMs) {
      // Everything in `prev` is older than one full window → expired. Drop
      // it, promote `live`, and start a fresh live bucket.
      prev = live;
      live = new Map();
      rotatedAt = Date.now();
    }
  }

  return {
    /**
     * Record an id; return true if it was already present (a replay).
     *
     * @param {string} id
     * @returns {boolean}
     */
    seen(id) {
      rotateIfDue();
      if (live.has(id) || prev.has(id)) {
        return true;
      }
      live.set(id, true);
      return false;
    },
    size() {
      return live.size + prev.size;
    },
    clear() {
      live = new Map();
      prev = new Map();
      rotatedAt = Date.now();
    },
  };
}
