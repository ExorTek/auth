import { SessionError, ErrorCode } from './errors.js';
import { generateSessionId, encodeToken, decodeToken } from './token.js';
import { memoryStore } from './stores/memory.js';
import { parseDuration } from './internal/duration.js';
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from './cookie.js';
import { extractTokenFromHeader } from './header.js';
import { computeFingerprint, readIp, readUserAgent } from './fingerprint.js';
import { deriveDeviceLabel } from './device-label.js';
import { createKeyMutex } from './internal/mutex.js';

/**
 * @typedef {import('./token.js').SessionTokenPayload} SessionTokenPayload
 * @typedef {import('./stores/memory.js').SessionStore} SessionStore
 * @typedef {import('./stores/memory.js').SessionRecord} SessionRecord
 * @typedef {import('./cookie.js').CookieOptions} CookieOptions
 * @typedef {import('./header.js').HeaderTokenConfig} HeaderTokenConfig
 */

/**
 * @typedef {object} SessionEvents
 * @property {(session: Session) => void | Promise<void>} [onIssue]
 * @property {(session: Session) => void | Promise<void>} [onVerify]
 * @property {(oldId: string, session: Session) => void | Promise<void>} [onRotate]
 * @property {(sessionId: string, reason?: string) => void | Promise<void>} [onRevoke]
 * @property {(reason: string, req: any) => void | Promise<void>} [onDeny]
 * @property {(payload: { userId: string | null, sessionId: string, reason: string, previous: object, current: object }) => void | Promise<void>} [onSuspicious]
 */

/**
 * @typedef {object} SessionManagerConfig
 * @property {string | Buffer | Uint8Array | Array<string | Buffer | Uint8Array>} secret
 * @property {string | number} ttl
 * @property {string | number} idleTtl
 * @property {CookieOptions & { name?: string }} [cookie]
 * @property {SessionStore} [store]
 * @property {HeaderTokenConfig} [headerToken]
 * @property {boolean} [anonymous=false]
 * @property {number} [concurrentLimit]
 * @property {ReadonlyArray<'ip' | 'ua'>} [bindTo]         Fingerprint binding.
 * @property {'strict' | 'soft'} [bindStrictness='strict'] Behaviour on fingerprint mismatch.
 *                                                        `strict` (default) — hard revoke,
 *                                                        verify returns null.
 *                                                        `soft` — fire `onSuspicious` with
 *                                                        `reason: 'fingerprint-mismatch'` but
 *                                                        let the request through. Useful for
 *                                                        mobile users who move between wifi
 *                                                        and 5G.
 * @property {boolean} [impersonation=false]               Enable impersonate() API.
 * @property {string | number} [impersonationTtl='30m']     Absolute lifetime of an
 *                                                          impersonation session. Defaults to
 *                                                          30 minutes — impersonation is a
 *                                                          high-risk mode; the tight window
 *                                                          matches AWS / GCP admin console
 *                                                          patterns and cuts audit surface.
 * @property {boolean} [deviceLabels=false]                Auto-generate device labels from UA.
 * @property {SessionEvents} [events]                      Audit trail callbacks.
 * @property {boolean | { onDetected?: SessionEvents['onSuspicious'] }} [suspiciousActivity]
 *                                                        IP-change detection.
 */

/**
 * @typedef {object} IssueOptions
 * @property {string | null} [userId=null]
 * @property {object} [claims={}]
 * @property {string} [deviceLabel]
 * @property {boolean} [rememberMe=false]
 * @property {number} [now]
 * @property {any} [req]                    When present, used to sample fingerprint (ip/ua).
 */

/**
 * @typedef {object} Session
 * @property {string} id
 * @property {string | null} userId
 * @property {object} claims
 * @property {number} issuedAt
 * @property {number} expiresAt
 * @property {number} lastSeenAt
 * @property {number} [freshAt]
 * @property {string} [deviceLabel]
 * @property {string} [ip]
 * @property {string} [ua]
 * @property {string} [impersonatedBy]
 * @property {string} [impersonationReason]
 * @property {boolean} isAnonymous
 */

/**
 * @typedef {object} IssueResult
 * @property {string} token
 * @property {string} cookie
 * @property {Session} session
 */

export function createSessionManager(config) {
  if (!config || typeof config !== 'object') {
    throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'createSessionManager: config is required');
  }
  const secret = normaliseSecret(config.secret);
  const ttlMs = parseDuration(config.ttl, 'ttl');
  const idleTtlMs = parseDuration(config.idleTtl, 'idleTtl');
  if (idleTtlMs > ttlMs) {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `createSessionManager: idleTtl (${idleTtlMs}ms) cannot exceed ttl (${ttlMs}ms)`,
    );
  }
  const cookieName = config.cookie?.name ?? '__Host-sid';
  const cookieOptions = { ...config.cookie };
  delete cookieOptions.name;
  const store = config.store ?? memoryStore();
  const headerToken = config.headerToken;
  const anonymousAllowed = config.anonymous === true;
  const concurrentLimit = config.concurrentLimit;
  const bindTo = Array.isArray(config.bindTo) ? Object.freeze([...config.bindTo]) : null;
  const bindStrictness = config.bindStrictness ?? 'strict';
  if (bindStrictness !== 'strict' && bindStrictness !== 'soft') {
    throw new SessionError(
      ErrorCode.INVALID_ARGUMENT,
      `createSessionManager: bindStrictness must be 'strict' | 'soft'; got '${bindStrictness}'`,
    );
  }
  const impersonationEnabled = config.impersonation === true;
  const impersonationTtlMs = impersonationEnabled
    ? parseDuration(config.impersonationTtl ?? '30m', 'impersonationTtl')
    : 0;
  const deviceLabelsAuto = config.deviceLabels === true;
  const events = config.events ?? {};
  const suspiciousActivity = normaliseSuspicious(config.suspiciousActivity, events);
  // Per-key mutex used to serialise the concurrent-limit check and the
  // rotate flow — both are read-modify-write cycles on a shared record
  // that would otherwise be prone to `active === limit` and
  // "same-token rotated twice" races. Only meaningful for the memory
  // store; distributed stores need their own atomic primitives.
  const mutex = createKeyMutex();

  if (bindTo) {
    for (const b of bindTo) {
      if (b !== 'ip' && b !== 'ua') {
        throw new SessionError(
          ErrorCode.INVALID_ARGUMENT,
          `createSessionManager: bindTo entries must be 'ip' | 'ua'; got '${b}'`,
        );
      }
    }
  }
  if (concurrentLimit !== undefined) {
    if (!Number.isInteger(concurrentLimit) || concurrentLimit < 1) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `createSessionManager: concurrentLimit must be a positive integer; got ${concurrentLimit}`,
      );
    }
  }

  function cookieFor(value, options = {}) {
    return serialiseCookie(cookieName, value, { ...cookieOptions, ...options });
  }
  function deleteCookie() {
    return serialiseDeleteCookie(cookieName, cookieOptions);
  }

  function projectSession(record) {
    /** @type {Session} */
    const out = {
      id: record.sid,
      userId: record.uid,
      claims: record.claims,
      issuedAt: record.issuedAt,
      expiresAt: record.expiresAt,
      lastSeenAt: record.lastSeenAt,
      isAnonymous: record.isAnonymous,
    };
    if (record.freshAt !== undefined) {
      out.freshAt = record.freshAt;
    }
    if (record.deviceLabel !== undefined) {
      out.deviceLabel = record.deviceLabel;
    }
    if (record.ip !== undefined) {
      out.ip = record.ip;
    }
    if (record.ua !== undefined) {
      out.ua = record.ua;
    }
    if (record.impersonatedBy !== undefined) {
      out.impersonatedBy = record.impersonatedBy;
    }
    if (record.impersonationReason !== undefined) {
      out.impersonationReason = record.impersonationReason;
    }
    return out;
  }

  async function issue(options = {}) {
    const now = options.now ?? Date.now();
    const userId = options.userId ?? null;
    if (userId === null && !anonymousAllowed) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        'issue: anonymous sessions are disabled — pass `anonymous: true` to createSessionManager or supply a userId',
      );
    }
    if (userId !== null && typeof userId !== 'string') {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `issue: userId must be a string or null; got ${typeof userId}`,
      );
    }
    // When the concurrent limit is enabled, the entire count →
    // evict-oldest → put sequence must run under a per-user mutex.
    // Wrapping only the check would still leave a race where two
    // parallel issues both see `active < limit` and both put — leaving
    // us at limit+1.
    if (concurrentLimit !== undefined && userId !== null) {
      return mutex.withLock(`limit:${userId}`, () => issueLocked(options, now, userId));
    }
    return issueLocked(options, now, userId);
  }

  async function issueLocked(options, now, userId) {
    if (concurrentLimit !== undefined && userId !== null) {
      const active = await store.countActive(userId);
      if (active >= concurrentLimit) {
        const list = await store.listByUser(userId);
        const oldest = list[list.length - 1];
        if (oldest) {
          await store.revoke(oldest.sid, 'concurrent-limit');
          await fire(events.onRevoke, oldest.sid, 'concurrent-limit');
        }
      }
    }
    const durationMs = options.rememberMe ? ttlMs * 2 : ttlMs;
    const expiresAt = now + durationMs;
    const claims = options.claims && typeof options.claims === 'object' ? options.claims : {};

    const req = options.req;
    const ip = req ? readIp(req) : undefined;
    const ua = req ? readUserAgent(req) : undefined;
    const fp = req && bindTo ? computeFingerprint(req, bindTo) : undefined;

    /** @type {SessionRecord} */
    const record = {
      sid: generateSessionId(),
      uid: userId,
      claims,
      issuedAt: now,
      expiresAt,
      lastSeenAt: now,
      isAnonymous: userId === null,
      revoked: false,
    };
    // Always sample ip/ua when a request is available — bindTo controls
    // whether they *invalidate* on mismatch (via fingerprint), but
    // suspicious-activity detection and the settings UI want the raw
    // values regardless.
    if (ip) {
      record.ip = ip;
    }
    if (ua) {
      record.ua = ua;
    }
    if (options.deviceLabel) {
      record.deviceLabel = String(options.deviceLabel);
    } else if (deviceLabelsAuto && ua) {
      const label = deriveDeviceLabel(ua);
      if (label) {
        record.deviceLabel = label;
      }
    }
    await store.put(record);

    const payload = {
      sid: record.sid,
      uid: record.uid,
      claims: record.claims,
      iat: record.issuedAt,
      exp: record.expiresAt,
    };
    if (fp) {
      payload.fp = fp;
    }
    const token = encodeToken(payload, secret[0], { now });
    const session = projectSession(record);
    await fire(events.onIssue, session);
    return {
      token,
      cookie: cookieFor(token, { maxAge: Math.floor(durationMs / 1000) }),
      session,
    };
  }

  async function verify(req, options = {}) {
    if (!req) {
      return null;
    }
    if (req.__exortekSession !== undefined) {
      return req.__exortekSession;
    }
    const now = options.now ?? Date.now();
    const token = extractToken(req);
    if (!token) {
      req.__exortekSession = null;
      return null;
    }
    /** @type {SessionTokenPayload} */
    let payload;
    try {
      payload = decodeToken(token, secret, { now });
    } catch (err) {
      req.__exortekSession = null;
      // All onDeny reasons are lowercase kebab — normalize the crypto/
      // session error codes (SCREAMING_SNAKE) into that shape so
      // consumers see a single vocabulary.
      const denyReason =
        err?.code === 'EXPIRED' ? 'expired' : err?.code === 'INVALID_TOKEN' ? 'invalid-token' : 'invalid-token';
      await fire(events.onDeny, denyReason, req);
      return null;
    }
    const record = await store.get(payload.sid);
    if (!record) {
      req.__exortekSession = null;
      await fire(events.onDeny, 'session-not-found', req);
      return null;
    }
    if (record.revoked) {
      req.__exortekSession = null;
      await fire(events.onDeny, 'revoked', req);
      return null;
    }
    if (record.expiresAt <= now) {
      req.__exortekSession = null;
      await fire(events.onDeny, 'expired', req);
      return null;
    }
    if (now - record.lastSeenAt > idleTtlMs) {
      await store.revoke(payload.sid, 'idle-timeout');
      req.__exortekSession = null;
      await fire(events.onDeny, 'idle-timeout', req);
      await fire(events.onRevoke, payload.sid, 'idle-timeout');
      return null;
    }
    // Fingerprint binding — payload carries the hash captured at issue.
    if (bindTo && payload.fp) {
      const current = computeFingerprint(req, bindTo);
      if (current !== payload.fp) {
        if (bindStrictness === 'soft') {
          // Soft mode: don't kill the session, but always emit a
          // suspicious-activity signal so the app can react (email the
          // user, force re-auth, whatever). Verify proceeds.
          if (suspiciousActivity) {
            await fire(suspiciousActivity.onDetected, {
              userId: record.uid,
              sessionId: record.sid,
              reason: 'fingerprint-mismatch',
              previous: { fp: payload.fp },
              current: { fp: current ?? null },
            });
          }
        } else {
          await store.revoke(payload.sid, 'fingerprint-mismatch');
          req.__exortekSession = null;
          await fire(events.onDeny, 'fingerprint-mismatch', req);
          await fire(events.onRevoke, payload.sid, 'fingerprint-mismatch');
          return null;
        }
      }
    }
    // Suspicious-activity: soft signal, doesn't revoke — flags for the app.
    if (suspiciousActivity && record.uid) {
      await detectSuspicious(req, record);
    }
    // Rolling touch.
    if (now - record.lastSeenAt > 1000) {
      await store.update(payload.sid, { lastSeenAt: now });
      record.lastSeenAt = now;
    }
    const session = projectSession(record);
    req.__exortekSession = session;
    await fire(events.onVerify, session);
    return session;
  }

  async function touch(sessionId, options = {}) {
    if (typeof sessionId !== 'string' || sessionId.length === 0) {
      throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'touch: sessionId is required');
    }
    const now = options.now ?? Date.now();
    const updated = await store.update(sessionId, { lastSeenAt: now });
    return updated !== null;
  }

  /**
   * Rotate the current request's session — mint a new token, revoke the
   * old server-side record. Standard practice after privilege
   * escalation, sensitive-action completion, or on a schedule.
   */
  async function rotate(req, options = {}) {
    const now = options.now ?? Date.now();
    const current = await verify(req, { now });
    if (!current) {
      throw new SessionError(ErrorCode.INVALID_TOKEN, 'rotate: no valid session to rotate');
    }
    return mutex.withLock(`rotate:${current.id}`, () => rotateLocked(req, current, options, now));
  }

  async function rotateLocked(req, current, options, now) {
    // Re-fetch under the lock — a parallel rotate may have already
    // consumed the session between our verify above and the lock
    // grant. When it did, the store has the session marked revoked
    // and we short-circuit rather than mint a duplicate.
    const oldRecord = await store.get(current.id);
    if (!oldRecord || oldRecord.revoked) {
      throw new SessionError(
        ErrorCode.SESSION_NOT_FOUND,
        'rotate: session was rotated or revoked by a concurrent request',
      );
    }
    // Fire suspicious-activity for context drift during rotate too — a
    // privilege-escalation flow initiated from a new IP is exactly the
    // shape of activity that deserves an alert.
    if (suspiciousActivity && oldRecord.uid) {
      await detectSuspicious(req, oldRecord);
    }
    // Kill the old record atomically before issuing the new one — a
    // concurrent verify against the old token now returns null.
    await store.revoke(current.id, 'rotated');
    await fire(events.onRevoke, current.id, 'rotated');

    // Preserve absolute expiry so the total session lifetime doesn't
    // extend — rotation should not become a way to keep an old session
    // alive forever.
    const expiresAt = oldRecord.expiresAt;
    const claims = options.claims ?? oldRecord.claims;

    /** @type {SessionRecord} */
    const next = {
      sid: generateSessionId(),
      uid: oldRecord.uid,
      claims,
      issuedAt: now,
      expiresAt,
      lastSeenAt: now,
      isAnonymous: oldRecord.isAnonymous,
      revoked: false,
    };
    if (oldRecord.freshAt !== undefined) {
      next.freshAt = oldRecord.freshAt;
    }
    if (oldRecord.deviceLabel !== undefined) {
      next.deviceLabel = oldRecord.deviceLabel;
    }
    if (oldRecord.ip !== undefined) {
      next.ip = oldRecord.ip;
    }
    if (oldRecord.ua !== undefined) {
      next.ua = oldRecord.ua;
    }
    if (oldRecord.impersonatedBy !== undefined) {
      next.impersonatedBy = oldRecord.impersonatedBy;
    }
    if (oldRecord.impersonationReason !== undefined) {
      next.impersonationReason = oldRecord.impersonationReason;
    }
    await store.put(next);

    const payload = {
      sid: next.sid,
      uid: next.uid,
      claims: next.claims,
      iat: next.issuedAt,
      exp: next.expiresAt,
    };
    if (bindTo) {
      const fp = computeFingerprint(req, bindTo);
      if (fp) {
        payload.fp = fp;
      }
    }
    const token = encodeToken(payload, secret[0], { now });
    // Invalidate the per-request cache so a subsequent `verify(req)`
    // sees the new session rather than the pre-rotate one.
    if (req && typeof req === 'object') {
      delete req.__exortekSession;
    }
    const session = projectSession(next);
    await fire(events.onRotate, current.id, session);
    const maxAge = Math.max(1, Math.floor((expiresAt - now) / 1000));
    return {
      token,
      cookie: cookieFor(token, { maxAge }),
      session,
      previousId: current.id,
    };
  }

  async function markFresh(req, options = {}) {
    const now = options.now ?? Date.now();
    const session = await verify(req, { now });
    if (!session) {
      throw new SessionError(ErrorCode.INVALID_TOKEN, 'markFresh: no valid session');
    }
    await store.update(session.id, { freshAt: now });
    if (req && typeof req === 'object') {
      // Bust the per-request cache so the caller sees the updated freshAt.
      delete req.__exortekSession;
    }
    return { freshAt: now };
  }

  async function requireFreshAuth(req, options = {}) {
    const maxAgeSeconds = options.maxAgeSeconds;
    if (typeof maxAgeSeconds !== 'number' || !Number.isFinite(maxAgeSeconds) || maxAgeSeconds <= 0) {
      throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'requireFreshAuth: maxAgeSeconds must be a positive number');
    }
    const now = options.now ?? Date.now();
    const session = await verify(req, { now });
    if (!session) {
      return false;
    }
    if (typeof session.freshAt !== 'number') {
      return false;
    }
    return now - session.freshAt <= maxAgeSeconds * 1000;
  }

  async function impersonate(adminReq, targetUserId, options = {}) {
    if (!impersonationEnabled) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        'impersonate: impersonation is disabled — pass `impersonation: true` to createSessionManager',
      );
    }
    if (typeof targetUserId !== 'string' || targetUserId.length === 0) {
      throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'impersonate: targetUserId is required');
    }
    const adminSession = await verify(adminReq);
    if (!adminSession || !adminSession.userId) {
      throw new SessionError(ErrorCode.INVALID_TOKEN, 'impersonate: admin session is not valid');
    }
    const now = options.now ?? Date.now();
    // Impersonation runs against its own (shorter) TTL — the regular
    // ttlMs would keep an admin's borrowed identity alive for the full
    // session window (7 days by default). Callers can override at the
    // config layer OR per-call via `options.ttl`.
    const durationMs = options.ttl ? parseDuration(options.ttl, 'impersonate.ttl') : impersonationTtlMs;
    const expiresAt = now + durationMs;
    /** @type {SessionRecord} */
    const record = {
      sid: generateSessionId(),
      uid: targetUserId,
      claims: options.claims ?? {},
      issuedAt: now,
      expiresAt,
      lastSeenAt: now,
      isAnonymous: false,
      revoked: false,
      impersonatedBy: adminSession.userId,
    };
    if (options.reason) {
      // Store the audit-trail reason as its own field, not smuggled
      // through the claims object.
      record.impersonationReason = String(options.reason);
    }
    await store.put(record);
    const payload = {
      sid: record.sid,
      uid: record.uid,
      claims: record.claims,
      iat: record.issuedAt,
      exp: record.expiresAt,
      imp: adminSession.userId,
    };
    const token = encodeToken(payload, secret[0], { now });
    const session = projectSession(record);
    await fire(events.onIssue, session);
    return {
      token,
      cookie: cookieFor(token, { maxAge: Math.floor(durationMs / 1000) }),
      session,
    };
  }

  async function revoke(req, options = {}) {
    const now = options.now ?? Date.now();
    const token = extractToken(req);
    if (!token) {
      return { cookie: deleteCookie(), revoked: false };
    }
    /** @type {SessionTokenPayload} */
    let payload;
    try {
      payload = decodeToken(token, secret, { now });
    } catch {
      return { cookie: deleteCookie(), revoked: false };
    }
    const revoked = await store.revoke(payload.sid, options.reason);
    if (revoked) {
      await fire(events.onRevoke, payload.sid, options.reason);
    }
    if (req && typeof req === 'object') {
      req.__exortekSession = null;
    }
    return { cookie: deleteCookie(), revoked };
  }

  async function revokeById(sessionId, options = {}) {
    if (typeof sessionId !== 'string' || sessionId.length === 0) {
      throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'revokeById: sessionId is required');
    }
    const revoked = await store.revoke(sessionId, options.reason);
    if (revoked) {
      await fire(events.onRevoke, sessionId, options.reason);
    }
    return revoked;
  }

  async function revokeAllForUser(userId, options = {}) {
    if (typeof userId !== 'string' || userId.length === 0) {
      throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'revokeAllForUser: userId is required');
    }
    const count = await store.revokeAllForUser(userId, options.reason);
    if (count > 0) {
      await fire(events.onRevoke, `user:${userId}`, options.reason ?? 'revoke-all-for-user');
    }
    return count;
  }

  async function revokeAllExceptCurrent(req, options = {}) {
    const session = await verify(req, { now: options.now });
    if (!session || !session.userId) {
      return 0;
    }
    const count = await store.revokeAllExcept(session.userId, session.id, options.reason);
    if (count > 0) {
      await fire(events.onRevoke, `user:${session.userId}:except:${session.id}`, options.reason ?? 'revoke-all-except');
    }
    return count;
  }

  async function listActive(userId) {
    if (typeof userId !== 'string' || userId.length === 0) {
      throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'listActive: userId is required');
    }
    const records = await store.listByUser(userId);
    return records.map(projectSession);
  }

  /**
   * Attach a userId to the currently-anonymous session on `req`.
   *
   *   const cart = anon.session.claims.cart
   *   await sessions.upgrade(req, userId, { mergeClaims: { cart } })
   *
   * The old anonymous record is revoked, a fresh session is issued
   * with the merged claims, and a new cookie is returned. Typical use
   * case is a guest checkout where the shopping cart lives on the
   * anonymous session and should survive the login.
   *
   * @param {any} req
   * @param {string} userId
   * @param {{ mergeClaims?: object, now?: number }} [options]
   * @returns {Promise<import('./manager.js').IssueResult>}
   */
  async function upgrade(req, userId, options = {}) {
    if (typeof userId !== 'string' || userId.length === 0) {
      throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'upgrade: userId is required');
    }
    const anon = await verify(req, { now: options.now });
    if (!anon) {
      throw new SessionError(ErrorCode.INVALID_TOKEN, 'upgrade: no valid session on the request');
    }
    if (!anon.isAnonymous) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        'upgrade: session is already authenticated — call rotate() or issue() instead',
      );
    }
    const merged =
      options.mergeClaims && typeof options.mergeClaims === 'object'
        ? { ...anon.claims, ...options.mergeClaims }
        : anon.claims;
    // Revoke the anonymous record and mint an authenticated session.
    await store.revoke(anon.id, 'upgraded');
    await fire(events.onRevoke, anon.id, 'upgraded');
    if (req && typeof req === 'object') {
      delete req.__exortekSession;
    }
    return issue({ userId, claims: merged, req, now: options.now });
  }

  // Compare current request context against the stored record and fire
  // `onDetected` for any drift. Called from both `verify` and `rotate`
  // so a state change during a privilege-escalation flow is caught too.
  async function detectSuspicious(req, record) {
    if (!suspiciousActivity || !record?.uid) {
      return;
    }
    const currentIp = readIp(req);
    if (currentIp && record.ip && currentIp !== record.ip) {
      await fire(suspiciousActivity.onDetected, {
        userId: record.uid,
        sessionId: record.sid,
        reason: 'ip-change',
        previous: { ip: record.ip },
        current: { ip: currentIp },
      });
    }
    const currentUa = readUserAgent(req);
    if (currentUa && record.ua && currentUa !== record.ua) {
      await fire(suspiciousActivity.onDetected, {
        userId: record.uid,
        sessionId: record.sid,
        reason: 'ua-change',
        previous: { ua: record.ua },
        current: { ua: currentUa },
      });
    }
  }

  function extractToken(req) {
    const headers = req?.headers;
    if (headerToken && headers) {
      const fromHeader = extractTokenFromHeader(headers, headerToken);
      if (fromHeader) {
        return fromHeader;
      }
    }
    if (!headers) {
      return undefined;
    }
    const cookieHeader = typeof headers.get === 'function' ? headers.get('cookie') : (headers.cookie ?? headers.Cookie);
    if (!cookieHeader) {
      return undefined;
    }
    const cookies = parseCookies(cookieHeader);
    return cookies[cookieName];
  }

  return {
    issue,
    verify,
    touch,
    rotate,
    markFresh,
    requireFreshAuth,
    impersonate,
    revoke,
    revokeById,
    revokeAllForUser,
    revokeAllExceptCurrent,
    listActive,
    upgrade,
    get cookieName() {
      return cookieName;
    },
    get store() {
      return store;
    },
    extractToken,
  };
}

function normaliseSecret(input) {
  if (input === undefined || input === null) {
    throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'createSessionManager: secret is required');
  }
  const list = Array.isArray(input) ? input : [input];
  if (list.length === 0) {
    throw new SessionError(ErrorCode.INVALID_ARGUMENT, 'createSessionManager: at least one secret is required');
  }
  for (const s of list) {
    if (typeof s !== 'string' && !Buffer.isBuffer(s) && !(s instanceof Uint8Array)) {
      throw new SessionError(
        ErrorCode.INVALID_ARGUMENT,
        `createSessionManager: secret entries must be string / Buffer / Uint8Array; got ${typeof s}`,
      );
    }
  }
  return list;
}

function normaliseSuspicious(input, events) {
  if (!input) {
    return null;
  }
  if (input === true) {
    return { onDetected: events.onSuspicious };
  }
  if (typeof input === 'object') {
    return { onDetected: input.onDetected ?? events.onSuspicious };
  }
  return null;
}

async function fire(callback, ...args) {
  if (typeof callback !== 'function') {
    return;
  }
  try {
    await callback(...args);
  } catch {
    // Swallow event callback errors — the caller's telemetry pipeline
    // should not be able to bring down a login flow.
  }
}
