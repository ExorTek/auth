import { isFunction, isString, isUndefined } from '@exortek/shared/predicates';

import { invalidArgument } from '../internal/guards.js';
import { ErrorCode, SessionError } from '../errors.js';

/**
 * @typedef {object} SessionRecord
 * @property {string} sid
 * @property {string | null} uid
 * @property {object} claims
 * @property {number} issuedAt
 * @property {number} expiresAt         Absolute TTL — after this the session is dead.
 * @property {number} lastSeenAt        Refreshed on `touch`; drives the idle-TTL check.
 * @property {number} [freshAt]         Last fresh-auth timestamp (sudo mode).
 * @property {string} [deviceLabel]
 * @property {string} [ip]
 * @property {string} [ua]
 * @property {string} [impersonatedBy]  Admin user ID if this is an impersonation.
 * @property {boolean} isAnonymous
 * @property {boolean} revoked          `true` once `revoke` has been called.
 * @property {string} [revokedReason]
 */

/**
 * @typedef {object} SessionStore
 * @property {(sid: string) => Promise<SessionRecord | null>} get
 * @property {(record: SessionRecord) => Promise<void>} put
 *   Insert-or-replace. Also updates the reverse `user → set(sid)` index.
 * @property {(sid: string, patch: Partial<SessionRecord>) => Promise<SessionRecord | null>} update
 *   Merge-patch a session. Returns the updated record, or `null` if the
 *   sid isn't present.
 * @property {(sid: string, reason?: string) => Promise<boolean>} revoke
 *   Mark a single session as revoked. Returns `true` if it was already
 *   in the store (whether previously revoked or not), `false` if not
 *   present.
 * @property {(uid: string, reason?: string) => Promise<number>} revokeAllForUser
 *   Revoke every session belonging to `uid`. Returns the count revoked.
 * @property {(uid: string, keepSid: string, reason?: string) => Promise<number>} revokeAllExcept
 *   Revoke every session for `uid` other than `keepSid`. Returns the
 *   count revoked.
 * @property {(uid: string) => Promise<SessionRecord[]>} listByUser
 *   Return every non-revoked, non-expired session for `uid`, newest first.
 * @property {(uid: string) => Promise<number>} countActive
 *   Number of non-revoked, non-expired sessions for `uid`. Cheaper than
 *   materialising the array when you only need the count.
 * @property {() => void} [_stop]
 *   Optional cleanup — memory store starts a sweep timer that
 *   `_stop()` cancels. Called from tests; production doesn't need it.
 */

/**
 * @typedef {object} MemoryStoreOptions
 * @property {number} [maxSessions=100000]
 *   Absolute cap on session count. Protects against a leaky app slowly
 *   filling process memory. When hit, expired/revoked entries are swept
 *   first; if still full, the least-recently-seen ANONYMOUS session is
 *   evicted before any authenticated one — so an anonymous-session
 *   flood can't force-logout real users. With `anonymous: true`, still
 *   pair this store with an IP rate limit on session creation.
 * @property {number} [sweepMs=60000]
 *   How often the store scans for expired entries and drops them.
 *   Deferred cleanup is fine — expired records never verify, and
 *   `listByUser` filters them out — but a periodic sweep keeps the
 *   backing map from ballooning.
 */

/**
 * In-process session store. Single-worker deployments and integration
 * tests only. For anything that runs across more than one Node process,
 * use `@exortek/session/stores/redis`.
 *
 * @param {MemoryStoreOptions} [options]
 * @returns {SessionStore}
 */
export function memoryStore(options = {}) {
  const maxSessions = options.maxSessions ?? 100_000;
  const sweepMs = options.sweepMs ?? 60_000;
  if (!Number.isInteger(maxSessions) || maxSessions < 1) {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `memoryStore: maxSessions must be a positive integer; got ${maxSessions}`,
    );
  }
  if (!Number.isInteger(sweepMs) || sweepMs < 1000) {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `memoryStore: sweepMs must be an integer ≥ 1000 ms; got ${sweepMs}`,
    );
  }

  /** @type {Map<string, SessionRecord>} */
  const map = new Map();
  /** @type {Map<string, Set<string>>} — user → set(sid) */
  const byUser = new Map();

  const sweep = () => {
    const now = Date.now();
    for (const [sid, rec] of map) {
      if (rec.revoked || rec.expiresAt <= now) {
        removeIndex(rec);
        map.delete(sid);
      }
    }
  };
  const timer = setInterval(sweep, sweepMs);
  if (isFunction(timer.unref)) {
    timer.unref();
  }

  function evict(sid) {
    const victim = map.get(sid);
    if (victim) {
      removeIndex(victim);
    }
    map.delete(sid);
  }

  function ensureRoom() {
    if (map.size < maxSessions) {
      return;
    }
    // Reclaim dead entries first — an authenticated session must never
    // be evicted while expired/revoked garbage is still occupying slots.
    sweep();
    if (map.size < maxSessions) {
      return;
    }
    // The map is kept in least-recently-seen order (update() re-inserts
    // on touch), so iteration order IS the LRU order. Prefer the oldest
    // ANONYMOUS session: with `anonymous: true` an attacker can mint
    // unlimited cookie-less sessions, and pure-LRU eviction would let
    // that flood push real users' authenticated sessions out (a mass
    // forced-logout DoS). Only when no anonymous session exists does
    // the oldest authenticated one go.
    let fallback = null;
    for (const [sid, rec] of map) {
      if (fallback === null) {
        fallback = sid;
      }
      if (rec.isAnonymous) {
        evict(sid);
        return;
      }
    }
    if (fallback !== null) {
      evict(fallback);
    }
  }

  function addIndex(rec) {
    if (rec.uid == null) {
      return;
    }
    let set = byUser.get(rec.uid);
    if (!set) {
      set = new Set();
      byUser.set(rec.uid, set);
    }
    set.add(rec.sid);
  }

  function removeIndex(rec) {
    if (rec.uid == null) {
      return;
    }
    const set = byUser.get(rec.uid);
    if (!set) {
      return;
    }
    set.delete(rec.sid);
    if (set.size === 0) {
      byUser.delete(rec.uid);
    }
  }

  function isActive(rec, now) {
    return !rec.revoked && rec.expiresAt > now;
  }

  return {
    async get(sid) {
      const rec = map.get(sid);
      return rec ?? null;
    },

    async put(record) {
      if (!record || !isString(record.sid)) {
        throw invalidArgument('memoryStore.put.record.sid must be a string');
      }
      const existing = map.get(record.sid);
      if (existing) {
        removeIndex(existing);
      } else {
        ensureRoom();
      }
      map.set(record.sid, record);
      addIndex(record);
    },

    async update(sid, patch) {
      const existing = map.get(sid);
      if (!existing) {
        return null;
      }
      const next = { ...existing, ...patch };
      if (patch.uid !== undefined && patch.uid !== existing.uid) {
        removeIndex(existing);
        addIndex(next);
      }
      // Delete-then-set keeps Map iteration order = LRU order, which
      // makes ensureRoom's eviction scan O(1) in the common case.
      if (!isUndefined(patch.lastSeenAt)) {
        map.delete(sid);
      }
      map.set(sid, next);
      return next;
    },

    async revoke(sid, reason) {
      const rec = map.get(sid);
      if (!rec) {
        return false;
      }
      rec.revoked = true;
      if (reason) {
        rec.revokedReason = reason;
      }
      map.set(sid, rec);
      return true;
    },

    async revokeAllForUser(uid, reason) {
      const set = byUser.get(uid);
      if (!set || set.size === 0) {
        return 0;
      }
      let count = 0;
      for (const sid of set) {
        const rec = map.get(sid);
        if (rec && !rec.revoked) {
          rec.revoked = true;
          if (reason) {
            rec.revokedReason = reason;
          }
          count++;
        }
      }
      return count;
    },

    async revokeAllExcept(uid, keepSid, reason) {
      const set = byUser.get(uid);
      if (!set || set.size === 0) {
        return 0;
      }
      let count = 0;
      for (const sid of set) {
        if (sid === keepSid) {
          continue;
        }
        const rec = map.get(sid);
        if (rec && !rec.revoked) {
          rec.revoked = true;
          if (reason) {
            rec.revokedReason = reason;
          }
          count++;
        }
      }
      return count;
    },

    async listByUser(uid) {
      const set = byUser.get(uid);
      if (!set) {
        return [];
      }
      const now = Date.now();
      const out = [];
      for (const sid of set) {
        const rec = map.get(sid);
        if (rec && isActive(rec, now)) {
          out.push(rec);
        }
      }
      out.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
      return out;
    },

    async countActive(uid) {
      const set = byUser.get(uid);
      if (!set) {
        return 0;
      }
      const now = Date.now();
      let count = 0;
      for (const sid of set) {
        const rec = map.get(sid);
        if (rec && isActive(rec, now)) {
          count++;
        }
      }
      return count;
    },

    _stop() {
      clearInterval(timer);
    },
  };
}
