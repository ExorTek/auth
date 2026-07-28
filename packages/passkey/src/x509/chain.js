/**
 * Minimal X.509 chain verification.
 *
 * WebAuthn attestations carry an `x5c` array of certificates, leaf
 * first, and the RP supplies a set of trust anchors. Verifying the
 * chain means walking leaf → root, checking each certificate's
 * signature against its issuer's public key, until we reach a
 * certificate that is in the RP's trust-anchor set.
 *
 * We do NOT accept a certificate as valid just because it happens
 * to be self-signed (issuer DN == subject DN, self-verified) —
 * that path was the anchor-bypass primitive behind
 * GHSA-6hxq-p678-4hr2 (fixed in `@simplewebauthn/server` 13.3.2).
 * A self-signed cert in `x5c` reaches acceptance ONLY when the RP
 * has explicitly registered it as an anchor.
 *
 * Intermediate certificates are recognised as trust anchors too
 * (matching `@simplewebauthn/server` v13.0 behaviour) — an RP may
 * pin an intermediate rather than the root.
 *
 * Reference: RFC 5280 §6 (Certification Path Validation).
 */

import { X509Certificate } from 'node:crypto';

/**
 * Coerce an input into an `X509Certificate`. Accepts:
 *   - an `X509Certificate` (returned unchanged)
 *   - a `Uint8Array` / `Buffer` of DER bytes
 *   - a PEM string
 *
 * @param {X509Certificate | Uint8Array | Buffer | string} input
 * @returns {X509Certificate}
 */
export function toCertificate(input) {
  if (input instanceof X509Certificate) {
    return input;
  }
  if (typeof input === 'string' || input instanceof Uint8Array) {
    return new X509Certificate(input);
  }
  throw new Error('x509.toCertificate: expected X509Certificate, Uint8Array, Buffer, or PEM string');
}

/**
 * Convenience: coerce an array of mixed inputs.
 *
 * @param {Array<X509Certificate | Uint8Array | Buffer | string>} inputs
 * @returns {X509Certificate[]}
 */
export function toCertificates(inputs) {
  if (!Array.isArray(inputs)) {
    throw new Error('x509.toCertificates: expected array');
  }
  return inputs.map(toCertificate);
}

/**
 * Look for the certificate in `anchors` that issued `cert`. We use
 * `X509Certificate#checkIssued`, which compares issuer / subject DN
 * per Node's built-in DN normaliser — safer than comparing the DN
 * strings Node exposes on `.subject` / `.issuer` (their format has
 * changed between Node versions).
 *
 * @param {X509Certificate} cert
 * @param {X509Certificate[]} anchors
 * @returns {X509Certificate | null}
 */
function findIssuerAnchor(cert, anchors) {
  for (const anchor of anchors) {
    if (cert.checkIssued(anchor)) {
      return anchor;
    }
  }
  return null;
}

/**
 * Look up whether `cert` is in the anchor set. Byte-equal DER
 * (via SHA-256 fingerprint) is the canonical identity check — DN
 * comparison alone is insufficient because two authorities can
 * share a DN.
 *
 * @param {X509Certificate} cert
 * @param {Set<string>} anchorFingerprints  hex-uppercase SHA-256 (Node default)
 * @returns {boolean}
 */
function isAnchor(cert, anchorFingerprints) {
  return anchorFingerprints.has(cert.fingerprint256);
}

/**
 * Verify a leaf-first certificate chain against a trust anchor set.
 *
 * Throws on any failure with a message that names the offending
 * position in the chain. Returns silently on success.
 *
 * Algorithm:
 *   for each certificate in the chain (leaf → root):
 *     - reject if outside its validity window at `now`
 *     - stop if this certificate is itself in the anchor set
 *     - otherwise locate the signer — next in the chain, or, if
 *       we've exhausted the chain, an anchor whose subject matches
 *       this certificate's issuer
 *     - reject if no such signer exists
 *     - verify DN linkage (`checkIssued`) and cryptographic
 *       signature (`verify(publicKey)`) against the signer
 *
 * @param {object} params
 * @param {Array<X509Certificate | Uint8Array | Buffer | string>} params.x5c
 *   Leaf first. Must be non-empty.
 * @param {Array<X509Certificate | Uint8Array | Buffer | string>} params.trustAnchors
 *   Root and/or intermediate certificates the RP trusts. Empty means
 *   the chain has no acceptable termination — the call will always
 *   throw. Callers that want to skip chain validation should not
 *   call this function.
 * @param {Date} [params.now]  clock reference for validity checks
 */
export function verifyChain({ x5c, trustAnchors, now = new Date() }) {
  const chain = toCertificates(x5c);
  const anchors = toCertificates(trustAnchors);

  if (chain.length === 0) {
    throw new Error('x509.verifyChain: x5c is empty');
  }
  if (anchors.length === 0) {
    throw new Error('x509.verifyChain: trustAnchors is empty — no chain would ever terminate');
  }
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new Error('x509.verifyChain: `now` must be a valid Date');
  }

  const anchorFingerprints = new Set(anchors.map(c => c.fingerprint256));

  for (let i = 0; i < chain.length; i += 1) {
    const current = chain[i];

    // `validFromDate` / `validToDate` are Node ≥ 21 getters that
    // parse the certificate's ASN.1 GeneralizedTime / UTCTime for
    // us. We target Node 22+, so they're always available.
    if (now < current.validFromDate || now > current.validToDate) {
      throw new Error(
        `x509.verifyChain: certificate ${i} outside validity window at ${now.toISOString()} (${current.validFrom} – ${current.validTo})`,
      );
    }

    // Chain terminates as soon as we reach a certificate the RP
    // trusts. Everything below has already been signature-verified.
    if (isAnchor(current, anchorFingerprints)) {
      return;
    }

    // Locate the signer. Preference: the next certificate in the
    // supplied chain. Falling back to an anchor whose subject DN
    // matches the current certificate's issuer DN is what makes
    // termination possible when the RP pinned a root/intermediate
    // that the authenticator did not embed in x5c.
    let signer;
    if (i + 1 < chain.length) {
      signer = chain[i + 1];
      if (!current.checkIssued(signer)) {
        throw new Error(`x509.verifyChain: certificate ${i} not issued by certificate ${i + 1} (DN mismatch)`);
      }
    } else {
      signer = findIssuerAnchor(current, anchors);
      if (!signer) {
        // This is the branch that stops a self-signed x5c leaf/root
        // from bypassing the anchor set — the CVE fix. If the
        // certificate is self-signed and not itself in `anchors`,
        // `findIssuerAnchor` cannot find any candidate (its issuer
        // DN only ever matches its own subject), and we throw here.
        throw new Error(
          `x509.verifyChain: no trust anchor terminates chain (leaf-most orphan subject: ${current.subject.replace(/\n/g, ' ')})`,
        );
      }
    }

    if (!current.verify(signer.publicKey)) {
      throw new Error(`x509.verifyChain: certificate ${i} signature does not verify against its issuer`);
    }
  }

  // Reaching this point means the last certificate in `chain`
  // wasn't itself an anchor but WAS signature-verified against an
  // anchor found via `findIssuerAnchor`. Chain accepted.
}
