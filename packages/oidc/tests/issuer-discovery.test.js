import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { ErrorCode } from '../src/index.js';
import { _clearIssuerMetadataCache, resolveIssuerMetadata } from '../src/internal/issuer-discovery.js';

afterEach(() => _clearIssuerMetadataCache());

/** A `fetch` that answers with headers at once and then streams `chunks`. */
function streamingFetch(chunks, { never = false } = {}) {
  return async (_url, init) =>
    new Response(
      new ReadableStream({
        pull(controller) {
          if (chunks.length) {
            controller.enqueue(new TextEncoder().encode(chunks.shift()));
          } else if (!never) {
            controller.close();
          } else {
            return new Promise((_resolve, reject) => {
              init.signal.addEventListener('abort', () => reject(init.signal.reason));
            });
          }
        },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
}

describe('resolveIssuerMetadata', () => {
  it('times out a metadata body that never finishes', async () => {
    await assert.rejects(
      resolveIssuerMetadata('https://op.example.com', {
        timeout: 50,
        fetchImpl: streamingFetch(['{"issuer":'], { never: true }),
      }),
      err => {
        assert.equal(err.code, ErrorCode.DISCOVERY_FAILED);
        assert.match(err.message, /timed out/);
        return true;
      },
    );
  });

  it('refuses a metadata document larger than 1 MB', async () => {
    const huge = Array.from({ length: 20 }, () => 'x'.repeat(64 * 1024));
    await assert.rejects(
      resolveIssuerMetadata('https://op.example.com', { fetchImpl: streamingFetch(['{"pad":"', ...huge, '"}']) }),
      err => {
        assert.equal(err.code, ErrorCode.DISCOVERY_FAILED);
        assert.match(err.message, /exceeds/);
        return true;
      },
    );
  });

  it('keeps a bounded number of issuers cached', async () => {
    let calls = 0;
    const fetchImpl = async url => {
      calls++;
      const issuer = new URL(url).origin;
      return new Response(JSON.stringify({ issuer }), { status: 200 });
    };
    for (let i = 0; i <= 100; i++) {
      await resolveIssuerMetadata(`https://op${i}.example.com`, { fetchImpl });
    }
    assert.equal(calls, 101);
    // The newest is still cached; the oldest was evicted and is fetched again.
    await resolveIssuerMetadata('https://op100.example.com', { fetchImpl });
    assert.equal(calls, 101);
    await resolveIssuerMetadata('https://op0.example.com', { fetchImpl });
    assert.equal(calls, 102);
  });
});
