import { createSessionManager } from './manager.js';
import { memoryStore } from './stores/memory.js';
import { SessionError, ErrorCode } from './errors.js';
import { generateSessionId, encodeToken, decodeToken } from './token.js';
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from './cookie.js';
import { extractTokenFromHeader } from './header.js';
import { deriveCsrfToken, verifyCsrfToken } from './csrf.js';
import { computeFingerprint, readIp, readUserAgent } from './fingerprint.js';
import { deriveDeviceLabel } from './device-label.js';
import { createTrustedDeviceCookie } from './trusted-device.js';

/**
 * @typedef {import('./manager.js').SessionManagerConfig} SessionManagerConfig
 * @typedef {import('./manager.js').IssueOptions} IssueOptions
 * @typedef {import('./manager.js').IssueResult} IssueResult
 * @typedef {import('./manager.js').Session} Session
 * @typedef {import('./manager.js').SessionEvents} SessionEvents
 * @typedef {import('./stores/memory.js').SessionStore} SessionStore
 * @typedef {import('./stores/memory.js').SessionRecord} SessionRecord
 * @typedef {import('./cookie.js').CookieOptions} CookieOptions
 * @typedef {import('./header.js').HeaderTokenConfig} HeaderTokenConfig
 * @typedef {import('./token.js').SessionTokenPayload} SessionTokenPayload
 */

export const sessionStore = Object.freeze({
  memory: memoryStore,
});

export {
  createSessionManager,
  createTrustedDeviceCookie,
  memoryStore,
  SessionError,
  ErrorCode,
  generateSessionId,
  encodeToken,
  decodeToken,
  parseCookies,
  serialiseCookie,
  serialiseDeleteCookie,
  extractTokenFromHeader,
  deriveCsrfToken,
  verifyCsrfToken,
  computeFingerprint,
  deriveDeviceLabel,
  readIp,
  readUserAgent,
};
