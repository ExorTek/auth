/**
 * `fetch` for server-to-server metadata calls (JWKS, OAuth token /
 * userinfo / discovery, OIDC metadata) with the guards every such call
 * needs and that are easy to get subtly wrong:
 *
 *   - one deadline over the WHOLE exchange. Clearing the timer once the
 *     headers arrive (the usual pattern) leaves the body read unbounded —
 *     a server that sends headers and then drips the body one byte at a
 *     time holds the caller (and anything awaiting it) indefinitely;
 *   - the body read stops at `maxBytes` while streaming, instead of
 *     buffering everything and measuring afterwards (`Content-Length` is
 *     only a hint, absent on a chunked response);
 *   - redirects are refused (`redirect: 'manual'`): a redirect from a
 *     metadata endpoint is never legitimate and is an SSRF lever.
 *
 * Status codes and JSON parsing stay with the caller, which raises its
 * own package error through `fail`.
 */

/**
 * @typedef {'timeout' | 'network' | 'redirect' | 'too_large'} FetchFailure
 *
 * @typedef {Object} FetchCappedOptions
 * @property {number} timeoutMs                 deadline for the request AND the body read
 * @property {number} maxBytes                  maximum body bytes buffered
 * @property {AbortSignal} [signal]             caller signal, combined with the deadline
 * @property {typeof fetch} [fetchImpl]         defaults to the global `fetch`
 * @property {(reason: FetchFailure, message: string, cause?: unknown) => Error} fail
 */

/**
 * @param {string} url
 * @param {RequestInit} init
 * @param {FetchCappedOptions} options
 * @returns {Promise<{ response: Response, text: string }>}
 */
export async function fetchCapped(url, init, options) {
  const { timeoutMs, maxBytes, signal: externalSignal, fetchImpl = fetch, fail } = options;
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), timeoutMs);
  const signal = externalSignal ? AbortSignal.any([deadline.signal, externalSignal]) : deadline.signal;

  try {
    /** @type {Response} */
    let response;
    try {
      response = await fetchImpl(url, { ...init, signal, redirect: 'manual' });
    } catch (err) {
      throw deadline.signal.aborted
        ? fail('timeout', `request to ${url} timed out after ${timeoutMs}ms`, err)
        : fail('network', `request to ${url} failed: ${err instanceof Error ? err.message : String(err)}`, err);
    }

    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel().catch(() => {});
      throw fail('redirect', `${url} returned a redirect (${response.status}) — refused for SSRF safety`);
    }

    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
      await response.body?.cancel().catch(() => {});
      throw fail('too_large', `${url} response exceeds ${maxBytes} bytes (declared ${declared})`);
    }

    let text;
    try {
      text = await readCapped(response, maxBytes, url, fail);
    } catch (err) {
      if (deadline.signal.aborted) {
        throw fail('timeout', `reading the response from ${url} timed out after ${timeoutMs}ms`, err);
      }
      throw err;
    }
    return { response, text };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * @param {Response} response
 * @param {number} limit
 * @param {string} url
 * @param {FetchCappedOptions['fail']} fail
 * @returns {Promise<string>}
 */
async function readCapped(response, limit, url, fail) {
  if (!response.body) {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > limit) {
      throw fail('too_large', `${url} response exceeds ${limit} bytes`);
    }
    return text;
  }
  const reader = response.body.getReader();
  /** @type {Uint8Array[]} */
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > limit) {
        throw fail('too_large', `${url} response exceeds ${limit} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).toString('utf8');
}
