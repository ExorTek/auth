import { isArray, isString } from '@exortek/shared/predicates';
import { assertRedisClient } from '@exortek/shared/redis-guard';
import { createRedisHelpers } from '@exortek/shared/redis-helpers';

import { invalidArgument } from '../internal/guards.js';

/**
 * @typedef {import('./memory.js').SessionStore} SessionStore
 * @typedef {import('./memory.js').SessionRecord} SessionRecord
 */

/**
 * @typedef {object} RedisStoreOptions
 * @property {string} [keyPrefix='sess:']
 *   Prefix for session keys — final key is `<prefix><sid>`. Reverse
 *   user index lives under `<prefix>u:<uid>`; revocation tombstones
 *   under `<prefix>rev:<sid>`.
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
 * DEL / SADD / SREM / SMEMBERS / PUBLISH commands — verified against
 * `ioredis` and `node-redis@4+`. The store never uses Lua scripts, so
 * `@upstash/redis` (HTTP client) also works. MGET / PEXPIRE are used
 * when the client supports them and gracefully skipped otherwise.
 *
 * Layout:
 *   `<prefix><sid>`          — JSON blob of the session record
 *   `<prefix>rev:<sid>`      — revocation tombstone (see below)
 *   `<prefix>u:<uid>`        — SADD-set of sids belonging to the user
 *   `<prefix>events`         — PUB/SUB channel for revocation events (optional)
 *
 * Every write sets an EXPIRE to the record's absolute TTL so revoked /
 * expired records naturally fall out of the DB — no sweep loop needed.
 *
 * **Why tombstones:** `update()` is a read-modify-write (GET → SET), so
 * a concurrent `revoke()` on another worker could be overwritten by an
 * in-flight update carrying the pre-revoke copy — silently un-revoking
 * the session. Revocations are therefore written to a separate
 * `<prefix>rev:<sid>` key that no update path ever touches; `get()` and
 * `listByUser()` overlay it onto the record. A revocation can never be
 * lost to a lost-update race. (Session IDs are base64url, so they can
 * never collide with the `rev:` / `u:` sub-prefixes.)
 *
 * @param {any} client
 * @param {RedisStoreOptions} [options]
 * @returns {SessionStore & { channel: string }}
 */
export function redisStore(client, options = {}) {
  assertRedisClient(client, ['get', 'set', 'del'], msg => {
    throw invalidArgument(`redisStore.client: ${msg}`);
  });
  const keyPrefix = options.keyPrefix ?? 'sess:';
  const publishRevocations = options.publishRevocations === true;
  const channel = options.channel ?? `${keyPrefix}events`;

  const sidKey = sid => `${keyPrefix}${sid}`;
  const revKey = sid => `${keyPrefix}rev:${sid}`;
  const userKey = uid => `${keyPrefix}u:${uid}`;

  const helpers = createRedisHelpers(client);

  function applyTombstone(record, rawTombstone) {
    if (!record || !rawTombstone) {
      return record;
    }
    record.revoked = true;
    const tomb = helpers.parseRecord(rawTombstone);
    if (tomb && isString(tomb.reason) && record.revokedReason === undefined) {
      record.revokedReason = tomb.reason;
    }
    return record;
  }

  async function readRecord(sid) {
    const [rawRecord, rawTombstone] = await helpers.mget([sidKey(sid), revKey(sid)]);
    const record = helpers.parseRecord(rawRecord);
    return record ? applyTombstone(record, rawTombstone) : null;
  }

  async function writeRecord(record, ttlMs) {
    await helpers.setWithTTL(sidKey(record.sid), JSON.stringify(record), ttlMs);
  }

  async function writeTombstone(sid, reason, ttlMs) {
    await helpers.setWithTTL(revKey(sid), JSON.stringify({ reason: reason ?? null, at: Date.now() }), ttlMs);
  }

  /**
   * Extend (never shorten) the user-index TTL so the `u:<uid>` set
   * falls out of Redis once its longest-lived session has expired.
   * Uses `PEXPIRE … GT` on Redis ≥ 7; falls back to a PTTL check on
   * older servers; silently no-ops on clients without pexpire.
   */
  async function bumpIndexTtl(uid, ttlMs) {
    const pexpire = client.pexpire?.bind(client) ?? client.pExpire?.bind(client);
    if (!pexpire) {
      return;
    }
    const key = userKey(uid);
    const px = Math.max(1, Math.ceil(ttlMs));
    const pttl = client.pttl?.bind(client) ?? client.pTTL?.bind(client);
    try {
      const applied = await pexpire(key, px, 'GT');
      if (applied === 1 || applied === true) {
        return;
      }
      if (pttl && (await pttl(key)) === -1) {
        await pexpire(key, px);
      }
      return;
    } catch {
      // Redis < 7 or a client that doesn't pass the GT flag through.
    }
    try {
      const current = pttl ? await pttl(key) : -1;
      if (typeof current !== 'number' || current < px) {
        await pexpire(key, px);
      }
    } catch {
      // Index TTL is an optimisation — never fail the write for it.
    }
  }

  async function indexAdd(uid, sid, ttlMs) {
    await helpers.sadd(userKey(uid), sid);
    await bumpIndexTtl(uid, ttlMs);
  }

  async function indexRemove(uid, sid) {
    await helpers.srem(userKey(uid), sid);
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

  async function fetchUserRecords(uid) {
    const sids = await helpers.smembers(userKey(uid));
    if (!isArray(sids) || sids.length === 0) {
      return [];
    }
    const raw = await helpers.mget([...sids.map(sidKey), ...sids.map(revKey)]);
    const out = [];
    const pruneOps = [];
    for (let i = 0; i < sids.length; i++) {
      const record = helpers.parseRecord(raw[i]);
      if (!record) {
        pruneOps.push(indexRemove(uid, sids[i]));
        out.push([sids[i], null]);
        continue;
      }
      out.push([sids[i], applyTombstone(record, raw[sids.length + i])]);
    }
    await Promise.all(pruneOps);
    return out;
  }

  async function revokeRecord(record, reason) {
    const ttlMs = Math.max(1, record.expiresAt - Date.now());
    await writeTombstone(record.sid, reason, ttlMs);
    record.revoked = true;
    if (reason) {
      record.revokedReason = reason;
    }
    await writeRecord(record, ttlMs);
    await publish(record.sid, reason);
  }

  return {
    channel,

    async get(sid) {
      return readRecord(sid);
    },

    async put(record) {
      if (!record || typeof record.sid !== 'string') {
        throw invalidArgument('redisStore.put.record.sid must be a string');
      }
      const ttlMs = Math.max(1, record.expiresAt - Date.now());
      await writeRecord(record, ttlMs);
      if (record.uid != null) {
        await indexAdd(record.uid, record.sid, ttlMs);
      }
    },

    async update(sid, patch) {
      const existing = await readRecord(sid);
      if (!existing) {
        return null;
      }
      const next = { ...existing, ...patch };
      const ttlMs = Math.max(1, next.expiresAt - Date.now());
      if (patch.uid !== undefined && patch.uid !== existing.uid) {
        if (existing.uid != null) {
          await indexRemove(existing.uid, sid);
        }
        if (next.uid != null) {
          await indexAdd(next.uid, sid, ttlMs);
        }
      }
      await writeRecord(next, ttlMs);
      return next;
    },

    async revoke(sid, reason) {
      const existing = await readRecord(sid);
      if (!existing) {
        return false;
      }
      await revokeRecord(existing, reason);
      return true;
    },

    async revokeAllForUser(uid, reason) {
      const pairs = await fetchUserRecords(uid);
      const targets = pairs.map(([, rec]) => rec).filter(rec => rec && !rec.revoked);
      await Promise.all(targets.map(rec => revokeRecord(rec, reason)));
      return targets.length;
    },

    async revokeAllExcept(uid, keepSid, reason) {
      const pairs = await fetchUserRecords(uid);
      const targets = pairs
        .filter(([sid]) => sid !== keepSid)
        .map(([, rec]) => rec)
        .filter(rec => rec && !rec.revoked);
      await Promise.all(targets.map(rec => revokeRecord(rec, reason)));
      return targets.length;
    },

    async listByUser(uid) {
      const pairs = await fetchUserRecords(uid);
      const now = Date.now();
      const out = pairs.map(([, rec]) => rec).filter(rec => rec && !rec.revoked && rec.expiresAt > now);
      out.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
      return out;
    },

    async countActive(uid) {
      const list = await this.listByUser(uid);
      return list.length;
    },
  };
}
