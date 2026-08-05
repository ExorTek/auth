/**
 * FAPI 2.0 profile (PLAN Tier C). A single `security.fapi` toggle bundles
 * the hardening the Financial-grade API Security Profile 2.0 mandates, so
 * a deployment opts into all of it at once instead of wiring each control:
 *
 *   - PAR required — authorization parameters go through the back channel
 *     only (RFC 9126).
 *   - PKCE S256 required — always on here anyway (Decision #0), FAPI can
 *     never turn it off.
 *   - Sender-constrained tokens — DPoP (RFC 9449) or mTLS (RFC 8705); this
 *     profile requires DPoP by default.
 *   - `iss` authorization response (RFC 9207) — always on here.
 *
 * The toggle only tightens: it can raise a requirement the base config
 * left optional, never relax one.
 */

/**
 * Derive the effective security flags from the base `security` config,
 * applying the FAPI profile when enabled.
 *
 * @param {{ fapi?: boolean, par?: { required?: boolean }, dpop?: { required?: boolean } }} security
 * @returns {{ fapi: boolean, requirePkce: boolean, requirePar: boolean, dpopRequired: boolean }}
 */
export function applyFapiProfile(security = {}) {
  const fapi = security.fapi === true;
  return {
    fapi,
    // PKCE S256 is mandatory on the code grant (OAuth 2.1 / Decision #0) —
    // there is no off-switch, so it is always on regardless of config.
    requirePkce: true,
    requirePar: fapi || security.par?.required === true,
    dpopRequired: fapi || security.dpop?.required === true,
  };
}
