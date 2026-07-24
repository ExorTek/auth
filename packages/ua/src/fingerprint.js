import { createHash } from 'node:crypto';
import { parse } from './index.js';

function expandIPv6(ip) {
  const parts = ip.split(':');
  const emptyIdx = parts.indexOf('');
  if (emptyIdx !== -1) {
    const filled = parts.filter(Boolean);
    const missing = 8 - filled.length;
    parts.splice(emptyIdx, parts.lastIndexOf('') - emptyIdx + 1, ...Array(missing).fill('0000'));
  }
  return parts
    .map(p => p.padStart(4, '0'))
    .slice(0, 8)
    .join(':');
}

/**
 * @typedef {Object} FingerprintOptions
 * @property {boolean} [includeIP=false]
 * @property {boolean} [subnet=false]
 * @property {boolean} [strict=true]
 * @property {string} [algorithm='sha256']
 */

/**
 * @typedef {Object} FingerprintInput
 * @property {string} [ua]
 * @property {Record<string, string>} [headers]
 * @property {string} [ip]
 */

/**
 * Create a deterministic fingerprint from request signals.
 *
 * Layers:
 * - **Stable** (always included): browser family, OS family, device type
 * - **Semi-stable** (included unless `strict: false`): browser major, OS version, Accept-Language
 * - **Volatile** (opt-in): IP subnet
 *
 *   import { createFingerprint } from '@exortek/ua/fingerprint';
 *
 *   const fp = createFingerprint({
 *     ua: req.headers['user-agent'],
 *     headers: req.headers,
 *     ip: req.ip,
 *   });
 *   // → 'fp_a8f3b2c1d4e5f6...'
 *
 * @param {FingerprintInput} input
 * @param {FingerprintOptions} [options]
 * @returns {string}
 */
export function createFingerprint(input, options) {
  const opts = options || {};
  const algo = opts.algorithm || 'sha256';

  const ua = input.ua || '';
  const headers = input.headers || {};
  const parsed = parse(ua, { headers, clientHints: true });

  const parts = [];

  // Stable layer (always)
  parts.push('b:' + (parsed.browser.name || ''));
  parts.push('os:' + (parsed.os.name || ''));
  parts.push('dt:' + (parsed.device.type || ''));

  // Semi-stable layer
  if (opts.strict !== false) {
    parts.push('bv:' + (parsed.browser.major || ''));
    parts.push('ov:' + (parsed.os.version || ''));

    const lang = headers['accept-language'] || '';
    const langNorm = lang
      .split(',')
      .map(l => l.split(';')[0].trim().toLowerCase())
      .filter(Boolean)
      .join(',');
    parts.push('lang:' + langNorm);
  }

  // Volatile layer (opt-in)
  if (input.ip && (opts.includeIP || opts.subnet)) {
    const ip = input.ip;
    if (opts.subnet) {
      if (ip.includes(':')) {
        parts.push('net:' + expandIPv6(ip).split(':').slice(0, 4).join(':'));
      } else {
        parts.push('net:' + ip.split('.').slice(0, 3).join('.'));
      }
    } else {
      parts.push('ip:' + ip);
    }
  }

  const raw = parts.join('|');
  const hash = createHash(algo).update(raw).digest('hex').substring(0, 32);

  return 'fp_' + hash;
}

/**
 * Create a fingerprint from a request object (Express/Fastify compatible).
 *
 *   import { fingerprintRequest } from '@exortek/ua/fingerprint';
 *
 *   app.use((req, res, next) => {
 *     req.fingerprint = fingerprintRequest(req);
 *     next();
 *   });
 *
 * @param {Object} req
 * @param {FingerprintOptions} [options]
 * @returns {string}
 */
export function fingerprintRequest(req, options) {
  const ua = req.headers?.['user-agent'] || '';
  const ip = req.ip || req.socket?.remoteAddress || '';

  return createFingerprint({ ua, headers: req.headers || {}, ip }, options);
}
