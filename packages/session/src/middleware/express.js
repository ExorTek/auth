import { createSessionManager } from '../manager.js';

/**
 * Express middleware factory. Populates:
 *
 *   - `req.session`   — the current `Session` or `null`
 *   - `req.sessions`  — the manager, for handlers to call `rotate`, etc.
 *   - `res.setSessionCookie(cookie)` — one-liner to install a token
 *   - `res.clearSessionCookie()`     — one-liner to install a delete-cookie
 *
 * @param {import('../manager.js').SessionManagerConfig | ReturnType<typeof createSessionManager>} configOrManager
 * @returns {{ manager, middleware }}
 */
export function sessionMiddleware(configOrManager) {
  const sessions =
    typeof configOrManager === 'object' && typeof configOrManager.issue === 'function'
      ? configOrManager
      : createSessionManager(configOrManager);

  const middleware = async function (req, res, next) {
    try {
      req.sessions = sessions;
      req.session = await sessions.verify(req);
      res.setSessionCookie = value => res.setHeader('Set-Cookie', appendCookie(res, value));
      res.clearSessionCookie = async () => {
        const result = await sessions.revoke(req);
        res.setHeader('Set-Cookie', appendCookie(res, result.cookie));
      };
      next();
    } catch (err) {
      next(err);
    }
  };
  return { manager: sessions, middleware };
}

/**
 * Multiple `Set-Cookie` values on one response are legal — `res.setHeader`
 * with an array is the canonical form. Preserve any existing cookies
 * (CSRF, tracking, feature flags) when appending our session cookie.
 */
function appendCookie(res, value) {
  const existing = res.getHeader('Set-Cookie');
  if (!existing) {
    return value;
  }
  return Array.isArray(existing) ? [...existing, value] : [existing, value];
}

export default sessionMiddleware;
