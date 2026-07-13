import { SessionError, ErrorCode } from '../errors.js';

/**
 * @typedef {import('./memory.js').SessionStore} SessionStore
 * @typedef {import('./memory.js').SessionRecord} SessionRecord
 */

/**
 * @typedef {object} RedisStoreOptions
 * @property {string} [keyPrefix='sess:']
 *   Prefix for session keys — final key is `<prefix><sid>`. Reverse
 *   user index lives under `<prefix>u:<uid>`.
 * @property {boolean} [publishRevocations=false]
 *   When true, revocations are published to the `<prefix>events`
 *   channel via `PUBLISH`. Other workers can subscribe to invalidate
 *   their per-request caches. Requires a Redis client that supports
 *   `.publish(channel, message)` (ioredis + node-redis both do).
 * @property {string} [channel]
 *   Override for the pub/sub channel. Defaults to `<keyPrefix>events`.
 */

/**
 * Redis session store. Works with any client that exposes the SET / GET /
 * DEL / SADD / SREM / SMEMBERS / EXPIRE / PUBLISH commands — verified
 * against `ioredis` and `node-redis@4+`. The store never uses Lua
 * scripts, so `@upstash/redis` (HTTP client) also works.
 *
 * Layout:
 *   `<prefix><sid>`          — HSET-style JSON blob of the session record
 *   `<prefix>u:<uid>`        — SADD-set of sids belonging to the user
 *   `<prefix>events`         — PUB/SUB channel for revocation events (optional)
 *
 * Every write sets an EXPIRE to the record's absolute TTL so revoked /
 * expired records naturally fall out of the DB — no sweep loop needed.
 *
 * @param {any} client
 * @param {RedisStoreOptions} [options]
 * @returns {SessionStore & { channel: string }}
 */
export function redisStore(client, options = {}) {
  if (!client || typeof client !== 'object') {
    throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'redisStore: client is required');
  }
  for (const method of ['get', 'set', 'del']) {
    if (typeof client[method] !== 'function') {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `redisStore: client is missing '${method}()' — pass an ioredis / node-redis client`,
      );
    }
  }
  const keyPrefix = options.keyPrefix ?? 'sess:';
  const publishRevocations = options.publishRevocations === true;
  const channel = options.channel ?? `${keyPrefix}events`;

  const sidKey = sid => `${keyPrefix}${sid}`;
  const userKey = uid => `${keyPrefix}u:${uid}`;

  async function readRecord(sid) {
    const raw = await client.get(sidKey(sid));
    if (!raw) {
      return null;
    }
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async function writeRecord(record, ttlMs) {
    const encoded = JSON.stringify(record);
    // ioredis uses `set(key, value, 'PX', ms)`; node-redis v4+ uses
    // `set(key, value, { PX: ms })`. Try the string-args form first
    // (works on both — node-redis's compatibility layer accepts it) and
    // fall through to the options-object form.
    try {
      await client.set(sidKey(record.sid), encoded, 'PX', Math.max(1, Math.ceil(ttlMs)));
    } catch {
      await client.set(sidKey(record.sid), encoded, { PX: Math.max(1, Math.ceil(ttlMs)) });
    }
  }

  async function sadd(uid, sid) {
    if (typeof client.sadd === 'function') {
      await client.sadd(userKey(uid), sid);
    } else if (typeof client.sAdd === 'function') {
      // node-redis v4 uses camelCase
      await client.sAdd(userKey(uid), sid);
    }
  }

  async function srem(uid, sid) {
    if (typeof client.srem === 'function') {
      await client.srem(userKey(uid), sid);
    } else if (typeof client.sRem === 'function') {
      await client.sRem(userKey(uid), sid);
    }
  }

  async function smembers(uid) {
    if (typeof client.smembers === 'function') {
      return client.smembers(userKey(uid));
    }
    if (typeof client.sMembers === 'function') {
      return client.sMembers(userKey(uid));
    }
    return [];
  }

  async function publish(sid, reason) {
    if (!publishRevocations || typeof client.publish !== 'function') {
      return;
    }
    try {
      await client.publish(channel, JSON.stringify({ type: 'revoke', sid, reason, at: Date.now() }));
    } catch {
      // A failed publish must not fail the revoke — degrade gracefully.
    }
  }

  return {
    channel,

    async get(sid) {
      const rec = await readRecord(sid);
      return rec ?? null;
    },

    async put(record) {
      if (!record || typeof record.sid !== 'string') {
        throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'redisStore.put: record.sid is required');
      }
      const ttlMs = Math.max(1, record.expiresAt - Date.now());
      await writeRecord(record, ttlMs);
      if (record.uid != null) {
        await sadd(record.uid, record.sid);
      }
    },

    async update(sid, patch) {
      const existing = await readRecord(sid);
      if (!existing) {
        return null;
      }
      const next = { ...existing, ...patch };
      if (patch.uid !== undefined && patch.uid !== existing.uid) {
        if (existing.uid != null) {
          await srem(existing.uid, sid);
        }
        if (next.uid != null) {
          await sadd(next.uid, sid);
        }
      }
      const ttlMs = Math.max(1, next.expiresAt - Date.now());
      await writeRecord(next, ttlMs);
      return next;
    },

    async revoke(sid, reason) {
      const existing = await readRecord(sid);
      if (!existing) {
        return false;
      }
      existing.revoked = true;
      if (reason) {
        existing.revokedReason = reason;
      }
      const ttlMs = Math.max(1, existing.expiresAt - Date.now());
      await writeRecord(existing, ttlMs);
      await publish(sid, reason);
      return true;
    },

    async revokeAllForUser(uid, reason) {
      const sids = await smembers(uid);
      if (!Array.isArray(sids) || sids.length === 0) {
        return 0;
      }
      let count = 0;
      for (const sid of sids) {
        const existing = await readRecord(sid);
        if (existing && !existing.revoked) {
          existing.revoked = true;
          if (reason) {
            existing.revokedReason = reason;
          }
          const ttlMs = Math.max(1, existing.expiresAt - Date.now());
          await writeRecord(existing, ttlMs);
          await publish(sid, reason);
          count++;
        }
      }
      return count;
    },

    async revokeAllExcept(uid, keepSid, reason) {
      const sids = await smembers(uid);
      if (!Array.isArray(sids) || sids.length === 0) {
        return 0;
      }
      let count = 0;
      for (const sid of sids) {
        if (sid === keepSid) {
          continue;
        }
        const existing = await readRecord(sid);
        if (existing && !existing.revoked) {
          existing.revoked = true;
          if (reason) {
            existing.revokedReason = reason;
          }
          const ttlMs = Math.max(1, existing.expiresAt - Date.now());
          await writeRecord(existing, ttlMs);
          await publish(sid, reason);
          count++;
        }
      }
      return count;
    },

    async listByUser(uid) {
      const sids = await smembers(uid);
      if (!Array.isArray(sids) || sids.length === 0) {
        return [];
      }
      const now = Date.now();
      const out = [];
      for (const sid of sids) {
        const rec = await readRecord(sid);
        if (rec && !rec.revoked && rec.expiresAt > now) {
          out.push(rec);
        } else if (!rec) {
          // Prune dead reference — key expired but the set kept the sid.
          await srem(uid, sid);
        }
      }
      out.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
      return out;
    },

    async countActive(uid) {
      const list = await this.listByUser(uid);
      return list.length;
    },
  };
}
