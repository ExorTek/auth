import { isString, isArray } from '@exortek/shared/predicates';
import { EMPTY, UA_MAX_LENGTH } from './constants.js';

/**
 * @param {string} str
 * @returns {string}
 */
export function lower(str) {
  return isString(str) ? str.toLowerCase() : '';
}

/**
 * @param {string} str
 * @param {number} [maxLen]
 * @returns {string}
 */
export function trim(str, maxLen) {
  const s = String(str).replace(/^\s+/, '');
  return maxLen === undefined ? s : s.substring(0, maxLen);
}

/**
 * @param {string|undefined} version
 * @returns {string|undefined}
 */
export function majorize(version) {
  if (!isString(version)) {
    return undefined;
  }
  return version.replace(/[^\d.]/g, '').split('.')[0] || undefined;
}

/**
 * @param {string} ua
 * @returns {string}
 */
export function sanitizeUA(ua) {
  if (!isString(ua)) {
    return '';
  }
  return trim(ua, UA_MAX_LENGTH);
}

/**
 * @param {string} header
 * @returns {Array<{brand: string, version: string}>|undefined}
 */
export function parseBrandList(header) {
  if (!header) {
    return undefined;
  }
  const safe = isString(header) ? header.substring(0, UA_MAX_LENGTH) : '';
  const items = [];
  for (const token of safe.split(',')) {
    const trimmed = token.trim().replace(/\\?"/g, '');
    if (trimmed.includes(';v=')) {
      const [brand, version] = trimmed.split(';v=');
      items.push({ brand: brand.trim(), version: version.trim() });
    }
  }
  return items.length > 0 ? items : undefined;
}

/**
 * @param {string} header
 * @returns {string|undefined}
 */
export function parseHeaderValue(header) {
  if (!isString(header)) {
    return undefined;
  }
  return trim(header.replace(/\\?"/g, ''), UA_MAX_LENGTH) || undefined;
}

/**
 * @param {string} str
 * @param {Record<string, string|string[]>} map
 * @returns {string|undefined}
 */
export function mapStr(str, map) {
  const lstr = lower(str);
  for (const [key, val] of Object.entries(map)) {
    if (isArray(val)) {
      for (const v of val) {
        if (lower(v) === lstr) {
          return key === '?' ? undefined : key;
        }
      }
    } else if (lower(val) === lstr) {
      return key === '?' ? undefined : key;
    }
  }
  return map['*'] !== undefined ? map['*'] : str;
}
