/**
 * Local JWKS — create and manage a key set for signing, with
 * zero-downtime rotation and a ready-made HTTP handler for
 * `/.well-known/jwks.json`.
 */

import { generate } from '@exortek/jwk/generate';
import { importJWK } from '@exortek/jwk/import';
import { toPublic } from '@exortek/jwk/export';
import { parseDuration } from '@exortek/shared/duration';
import { isString } from '@exortek/shared/predicates';
import { JwksError, ErrorCode } from './errors.js';
import { assertNonEmptyString, assertObject, invalidArgument } from './internal/guards.js';

/**
 * @typedef {object} KeySpec
 * @property {string}  alg             algorithm identifier (e.g. 'ES256', 'EdDSA', 'RS256')
 * @property {string}  [use='sig']     JWK use parameter
 * @property {string}  [kid]           explicit kid — auto-generated if omitted
 * @property {string}  [curve]         EC/OKP curve (default per kty)
 * @property {number}  [modulusLength] RSA modulus length (default 2048)
 */

/**
 * @typedef {object} LocalKeySetOptions
 * @property {string|number} [gracePeriod='24h'] how long a rotated key stays in the set for verification
 */

/**
 * @typedef {object} KeyEntry
 * @property {string}                  kid
 * @property {string}                  alg
 * @property {Record<string, unknown>} privateJwk
 * @property {Record<string, unknown>} publicJwk
 * @property {number}                  createdAt
 * @property {number}                  [retiredAt]
 */

/**
 * @typedef {object} RotateOptions
 * @property {string}  alg             algorithm of the key to rotate
 * @property {string}  [kid]           explicit kid for the new key
 * @property {string}  [curve]         curve override for EC/OKP
 * @property {number}  [modulusLength] RSA modulus override
 */

/**
 * @typedef {object} HandlerOptions
 * @property {string} [cacheControl='public, max-age=300'] Cache-Control header value
 */

/**
 * @typedef {object} LocalKeySet
 * @property {() => { keys: Record<string, unknown>[] }}  toJSON
 * @property {(alg?: string) => KeyEntry | null}          getSigningKey
 * @property {string[]}                                   kids
 * @property {number}                                     size
 * @property {(options: RotateOptions) => Promise<KeyEntry>} rotate
 * @property {(privateJwk: Record<string, unknown>) => void} addKey
 * @property {(options?: HandlerOptions) => (req: unknown, res: import('node:http').ServerResponse) => void} handler
 * @property {(header: { kid: string, alg?: string }) => Promise<import('node:crypto').KeyObject>} resolve
 */

/** @type {Record<string, string>} */
const ALG_TO_KTY = {
  ES256: 'EC',
  ES384: 'EC',
  ES512: 'EC',
  RS256: 'RSA',
  RS384: 'RSA',
  RS512: 'RSA',
  PS256: 'RSA',
  PS384: 'RSA',
  PS512: 'RSA',
  EdDSA: 'OKP',
};

/** @type {Record<string, string>} */
const ALG_TO_CURVE = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
  EdDSA: 'Ed25519',
};

let kidCounter = 0;

/**
 * @param {string} alg
 * @returns {string}
 */
function generateKid(alg) {
  return `${alg.toLowerCase()}-${Date.now().toString(36)}-${(++kidCounter).toString(36)}`;
}

/**
 * Create a local key set from one or more key specifications.
 *
 * @param {KeySpec[]} specs
 * @param {LocalKeySetOptions} [options]
 * @returns {Promise<LocalKeySet>}
 */
export async function createLocalKeySet(specs, options = {}) {
  if (!Array.isArray(specs) || specs.length === 0) {
    throw invalidArgument('createLocalKeySet.specs must be a non-empty array of key specifications');
  }

  const gracePeriod = parseDuration(options.gracePeriod ?? '24h');

  /** @type {KeyEntry[]} */
  const keys = [];

  for (const spec of specs) {
    assertObject(spec, 'createLocalKeySet.specs[]');
    assertNonEmptyString(spec.alg, 'createLocalKeySet.specs[].alg');

    const alg = spec.alg;
    const kty = ALG_TO_KTY[alg];
    if (!kty) {
      throw invalidArgument(`createLocalKeySet: unsupported algorithm ${JSON.stringify(alg)}`);
    }

    const kid = isString(spec.kid) && spec.kid !== '' ? spec.kid : generateKid(alg);
    const use = spec.use ?? 'sig';

    const genOptions = { kid, alg, use };
    if (kty === 'EC' || kty === 'OKP') {
      genOptions.curve = spec.curve ?? ALG_TO_CURVE[alg];
    }
    if (kty === 'RSA') {
      genOptions.modulusLength = spec.modulusLength ?? 2048;
    }

    const { publicJwk, privateJwk } = await generate(kty, genOptions);

    keys.push({ kid, alg, privateJwk, publicJwk, createdAt: Date.now() });
  }

  function sweepRetired() {
    const now = Date.now();
    for (let i = keys.length - 1; i >= 0; i--) {
      if (keys[i].retiredAt && now - keys[i].retiredAt > gracePeriod) {
        keys.splice(i, 1);
      }
    }
  }

  function activeKeys() {
    return keys.filter(k => !k.retiredAt);
  }

  function buildPublicJwks() {
    sweepRetired();
    return { keys: keys.map(k => ({ ...k.publicJwk })) };
  }

  return {
    /**
     * The public JWK Set document — suitable for `JSON.stringify` and
     * serving at `/.well-known/jwks.json`. Includes retired keys
     * still within the grace period.
     *
     * @returns {{ keys: Record<string, unknown>[] }}
     */
    toJSON() {
      return buildPublicJwks();
    },

    /**
     * Get the active signing key for a given algorithm. Returns the
     * most recently added non-retired key matching `alg`.
     *
     * @param {string} [alg]
     * @returns {KeyEntry | null}
     */
    getSigningKey(alg) {
      const candidates = activeKeys().filter(k => !alg || k.alg === alg);
      return candidates.length > 0 ? candidates[candidates.length - 1] : null;
    },

    /**
     * All kid values (active + grace-period retired).
     * @returns {string[]}
     */
    get kids() {
      sweepRetired();
      return keys.map(k => k.kid);
    },

    /**
     * Count of keys (active + grace-period retired).
     * @returns {number}
     */
    get size() {
      sweepRetired();
      return keys.length;
    },

    /**
     * Rotate a key by algorithm — retire the current one and generate
     * a fresh replacement. The retired key stays in the set for
     * `gracePeriod` so in-flight tokens signed with it can still verify.
     *
     * @param {RotateOptions} rotateOptions
     * @returns {Promise<KeyEntry>}
     */
    async rotate(rotateOptions) {
      assertObject(rotateOptions, 'rotate.options');
      assertNonEmptyString(rotateOptions.alg, 'rotate.options.alg');

      const alg = rotateOptions.alg;
      const kty = ALG_TO_KTY[alg];
      if (!kty) {
        throw invalidArgument(`rotate: unsupported algorithm ${JSON.stringify(alg)}`);
      }

      const now = Date.now();
      for (const k of keys) {
        if (k.alg === alg && !k.retiredAt) {
          k.retiredAt = now;
        }
      }

      const kid = isString(rotateOptions.kid) && rotateOptions.kid !== '' ? rotateOptions.kid : generateKid(alg);
      const genOptions = { kid, alg, use: 'sig' };
      if (kty === 'EC' || kty === 'OKP') {
        genOptions.curve = rotateOptions.curve ?? ALG_TO_CURVE[alg];
      }
      if (kty === 'RSA') {
        genOptions.modulusLength = rotateOptions.modulusLength ?? 2048;
      }

      const { publicJwk, privateJwk } = await generate(kty, genOptions);
      const entry = { kid, alg, privateJwk, publicJwk, createdAt: now };
      keys.push(entry);
      sweepRetired();

      return entry;
    },

    /**
     * Add an existing key pair to the set (e.g. imported from storage).
     * Throws if a key with the same `kid` already exists.
     *
     * @param {Record<string, unknown>} privateJwk
     */
    addKey(privateJwk) {
      assertObject(privateJwk, 'addKey.privateJwk');
      const kid = privateJwk.kid;
      const alg = privateJwk.alg;
      if (!isString(kid) || kid === '') {
        throw invalidArgument('addKey: privateJwk must have a "kid" property');
      }
      if (!isString(alg) || alg === '') {
        throw invalidArgument('addKey: privateJwk must have an "alg" property');
      }
      if (keys.some(k => k.kid === kid)) {
        throw invalidArgument(`addKey: a key with kid=${JSON.stringify(kid)} already exists in the set`);
      }
      const publicJwk = toPublic(privateJwk);
      keys.push({
        kid: /** @type {string} */ (kid),
        alg: /** @type {string} */ (alg),
        privateJwk: { ...privateJwk },
        publicJwk,
        createdAt: Date.now(),
      });
    },

    /**
     * HTTP handler for `/.well-known/jwks.json`. Uses the Node.js
     * `http.ServerResponse` API which Express and Fastify both support.
     *
     * @param {HandlerOptions} [handlerOptions]
     * @returns {(req: unknown, res: import('node:http').ServerResponse) => void}
     */
    handler(handlerOptions = {}) {
      const cacheControl = handlerOptions.cacheControl ?? 'public, max-age=300';
      return function jwksHandler(_req, /** @type {import('node:http').ServerResponse} */ res) {
        const json = JSON.stringify(buildPublicJwks());
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': cacheControl,
        });
        res.end(json);
      };
    },

    /**
     * Resolver function compatible with `jwt.verify(token, resolver)`.
     * Looks up a key by `kid` header with optional `alg` cross-check.
     *
     * @param {{ kid: string, alg?: string }} header
     * @returns {Promise<import('node:crypto').KeyObject>}
     */
    async resolve(header) {
      const kid = header?.kid;
      sweepRetired();
      const entry = keys.find(k => k.kid === kid);
      if (!entry) {
        throw new JwksError(ErrorCode.KID_NOT_FOUND, `no key with kid=${JSON.stringify(kid)} in local key set`);
      }
      if (isString(header.alg) && entry.alg && entry.alg !== header.alg) {
        throw new JwksError(
          ErrorCode.KID_NOT_FOUND,
          `kid=${JSON.stringify(kid)} found but alg mismatch: key has ${entry.alg}, token has ${header.alg}`,
        );
      }
      return importJWK(entry.publicJwk);
    },
  };
}
