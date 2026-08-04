/**
 * DPoP — Demonstrating Proof-of-Possession (RFC 9449). A client proves it
 * holds a private key by sending a per-request `DPoP` proof JWT; the
 * server binds the issued access/refresh tokens to that key's thumbprint
 * (`cnf.jkt`), so a stolen bearer token is useless without the key. This
 * is the single biggest 2025–2026 anti-token-theft measure (FAPI 2.0,
 * open banking).
 *
 * At the token endpoint we validate the proof (type, asymmetric alg,
 * embedded public JWK, signature, `htm`/`htu`, freshness, replay) and
 * return the key thumbprint the grant binds the tokens to. A `null`
 * proof is allowed only when neither the client nor the server requires
 * DPoP — otherwise it is `invalid_dpop_proof`.
 */
import { importJWK, thumbprint } from '@exortek/jwk';
import { verify as jwsVerify, decodeProtectedHeader } from '@exortek/jws';
import { isNonEmptyString, isObject } from '@exortek/shared/predicates';

import { ProtocolError, ServerError } from '../errors.js';

// RFC 9449 §4.2 — the proof `alg` must be an asymmetric JWS alg; symmetric
// and `none` are rejected so the embedded JWK is a real public key.
const ALLOWED_ALGS = new Set([
  'ES256',
  'ES384',
  'ES512',
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'EdDSA',
]);
// Proofs are single-use and short-lived; §4.3 recommends a small window.
const MAX_PROOF_AGE_MS = 60_000;

// Replay cache: a proof `jti` may be used once. Module-level with lazy
// eviction — a deployment fronting multiple nodes overrides this with a
// shared store via config.stores if it needs cross-node replay defense.
/** @type {Map<string, number>} */
const seenJti = new Map();

/**
 * Resolve the DPoP binding for a token-endpoint request.
 *
 * @param {import('../request.js').ServerRequest} req
 * @param {Record<string, any>} config
 * @param {import('../clients.js').Client} client
 * @returns {Promise<{ dpopJkt: string | undefined, nonceHeaders: Record<string, string> }>}
 */
export async function resolveDpopBinding(req, config, client) {
  const proof = req.header('dpop');
  const required = config.dpopRequired === true || client.dpopBoundAccessTokens === true;

  if (!isNonEmptyString(proof)) {
    if (required) {
      throw new ServerError(ProtocolError.INVALID_DPOP_PROOF, 'this client requires a DPoP proof');
    }
    return { dpopJkt: undefined, nonceHeaders: {} };
  }

  const jkt = await verifyDpopProof(proof, {
    htm: req.method,
    htu: config.endpoints.token,
  });
  return { dpopJkt: jkt, nonceHeaders: {} };
}

/**
 * Verify a DPoP proof JWT and return its key thumbprint (`jkt`).
 *
 * @param {string} proof
 * @param {{ htm: string, htu: string }} binding
 * @returns {Promise<string>}
 */
export async function verifyDpopProof(proof, binding) {
  let header;
  try {
    header = decodeProtectedHeader(proof);
  } catch {
    throw invalidProof('DPoP proof is not a well-formed JWT');
  }

  if (header.typ !== 'dpop+jwt') {
    throw invalidProof('DPoP proof typ must be dpop+jwt');
  }
  if (!isNonEmptyString(header.alg) || !ALLOWED_ALGS.has(header.alg)) {
    throw invalidProof(`DPoP proof alg ${JSON.stringify(header.alg)} is not an accepted asymmetric algorithm`);
  }
  if (!isObject(header.jwk) || isNonEmptyString(header.jwk.d)) {
    // An embedded PRIVATE key (has `d`) is a client blunder / attack.
    throw invalidProof('DPoP proof must embed a public JWK');
  }

  let key;
  let jkt;
  try {
    key = await importJWK(header.jwk);
    jkt = await thumbprint(header.jwk);
  } catch {
    throw invalidProof('DPoP proof embeds an unusable JWK');
  }

  let payload;
  try {
    ({ payload } = await jwsVerify(proof, key, { alg: [header.alg] }));
  } catch {
    throw invalidProof('DPoP proof signature is invalid');
  }

  // htm / htu bind the proof to THIS request (RFC 9449 §4.3). htu is
  // compared without query or fragment.
  if (payload.htm !== binding.htm) {
    throw invalidProof('DPoP proof htm does not match the request method');
  }
  if (normalizeHtu(payload.htu) !== normalizeHtu(binding.htu)) {
    throw invalidProof('DPoP proof htu does not match the request URI');
  }
  assertFresh(payload.iat);
  assertUnique(payload.jti);

  return jkt;
}

/**
 * @param {unknown} htu
 * @returns {string}
 */
function normalizeHtu(htu) {
  if (!isNonEmptyString(htu)) {
    return '';
  }
  try {
    const url = new URL(htu);
    url.hash = '';
    url.search = '';
    return url.href;
  } catch {
    return htu;
  }
}

/** @param {unknown} iat */
function assertFresh(iat) {
  if (typeof iat !== 'number') {
    throw invalidProof('DPoP proof is missing iat');
  }
  const ageMs = Date.now() - iat * 1000;
  if (ageMs > MAX_PROOF_AGE_MS || ageMs < -MAX_PROOF_AGE_MS) {
    throw invalidProof('DPoP proof iat is outside the acceptable window');
  }
}

/** @param {unknown} jti */
function assertUnique(jti) {
  if (!isNonEmptyString(jti)) {
    throw invalidProof('DPoP proof is missing jti');
  }
  const now = Date.now();
  // Lazy eviction of expired jtis keeps the map bounded without a timer.
  if (seenJti.size > 1024) {
    for (const [id, exp] of seenJti) {
      if (exp <= now) {
        seenJti.delete(id);
      }
    }
  }
  if (seenJti.has(jti)) {
    throw invalidProof('DPoP proof jti has already been used (replay)');
  }
  seenJti.set(jti, now + MAX_PROOF_AGE_MS);
}

/** @param {string} message @returns {ServerError} */
function invalidProof(message) {
  return new ServerError(ProtocolError.INVALID_DPOP_PROOF, message);
}

/** Test hook — clear the replay cache between cases. */
export function _clearDpopReplayCache() {
  seenJti.clear();
}
