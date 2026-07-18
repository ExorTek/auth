/**
 * Framework-agnostic HTTP helpers. The intent here is *primitives*,
 * not "adapter kit" — anything that reads or writes framework state
 * belongs in the framework file, not here.
 */

/**
 * Append a `Set-Cookie` value to an existing header value, returning
 * whatever shape the caller should hand back to their framework.
 *
 *   undefined → value (string)
 *   string    → [existing, value]
 *   string[]  → [...existing, value]
 *
 * Multiple `Set-Cookie` values on one response are legal (RFC 7230
 * §3.2.2). Every framework this repo targets accepts an array as the
 * canonical multi-cookie form; those that need string / string form
 * (e.g. Fastify `reply.header('Set-Cookie', v)` REPLACES the current
 * value) still take the array shape.
 *
 * @param {string | string[] | undefined | null} existing
 * @param {string} value
 * @returns {string | string[]}
 */
export function appendSetCookieHeader(existing, value) {
  if (!existing) {
    return value;
  }
  return Array.isArray(existing) ? [...existing, value] : [existing, value];
}
