import { createSessionManager } from './manager.js';
import { memoryStore } from './stores/memory.js';
import { SessionError, ErrorCode } from './errors.js';
import { generateSessionId, encodeToken, decodeToken } from './token.js';
import { parseCookies, serialiseCookie, serialiseDeleteCookie } from './cookie.js';
import { deriveCsrfToken, verifyCsrfToken, maskCsrfToken, unmaskCsrfToken } from './csrf.js';
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
  deriveCsrfToken,
  verifyCsrfToken,
  maskCsrfToken,
  unmaskCsrfToken,
  computeFingerprint,
  deriveDeviceLabel,
  readIp,
  readUserAgent,
};
