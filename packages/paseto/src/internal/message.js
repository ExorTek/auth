/**
 * Shared payload / footer (de)serialisation for the high-level v4.local
 * and v4.public APIs. Keeps JSON + claim handling in one place so
 * `local.js` and `public.js` only wire the crypto.
 */

import { isString, isObject, isBytes } from '@exortek/shared/predicates';

import { applyClaims, validateClaims } from './claims.js';
import { invalidArgument } from './guards.js';

/** Coerce `undefined | string | bytes` to a Buffer. */
export function toBuffer(value, name) {
  if (value === undefined || value === null) {
    return Buffer.alloc(0);
  }
  if (isString(value)) {
    return Buffer.from(value, 'utf8');
  }
  if (isBytes(value)) {
    return Buffer.from(value);
  }
  throw invalidArgument(`${name} must be a string or byte buffer`);
}

/**
 * Serialise the payload into message bytes. Objects get the registered
 * claims applied and are JSON-encoded; strings and byte buffers pass
 * through untouched (no claims).
 *
 * @param {Record<string, unknown> | string | Uint8Array} payload
 * @param {object} options   claim options (expiresIn, issuer, …)
 * @returns {Buffer}
 */
export function serializePayload(payload, options) {
  if (isObject(payload)) {
    return Buffer.from(JSON.stringify(applyClaims(payload, options)), 'utf8');
  }
  if (isString(payload) || isBytes(payload)) {
    return toBuffer(payload, 'payload');
  }
  throw invalidArgument('payload must be an object, string, or byte buffer');
}

/** Serialise the footer (object → JSON, string/bytes pass through). */
export function serializeFooter(footer) {
  if (isObject(footer)) {
    return Buffer.from(JSON.stringify(footer), 'utf8');
  }
  return toBuffer(footer, 'footer');
}

/**
 * Turn decrypted/verified message bytes back into the caller's result:
 * parse JSON when it is an object, validate registered claims, and
 * optionally return the `{ payload, footer }` envelope.
 *
 * @param {Buffer} message
 * @param {Buffer} footer
 * @param {object} options
 * @param {string} purpose   'local' | 'public'
 */
export function finalize(message, footer, options, purpose) {
  const text = message.toString('utf8');

  let payload = text;
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (isObject(payload)) {
    validateClaims(payload, options);
  }

  if (options.complete === true) {
    return { payload, footer: footer.toString('utf8'), version: 'v4', purpose };
  }
  return payload;
}
