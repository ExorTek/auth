import { ImageResponse } from 'next/og';

// Dynamic Open Graph image endpoint. Pages point their openGraph/twitter image
// at /og?title=…&desc=… (see [[...mdxPath]]/page.jsx generateMetadata) so each
// share card is specific to the page. A route handler is used rather than a
// file-based opengraph-image because the optional catch-all segment cannot
// carry a static metadata child (the catch-all must be the last segment).
export const contentType = 'image/png';

const SIZE = { width: 1200, height: 630 };
const BG = '#17181c';
const CREAM = '#e4dcc7';
const GREEN = '#12b76a';
const MUTED = '#8a8f99';

export function GET(request) {
  const { searchParams } = new URL(request.url);
  const heading = (searchParams.get('title') || '@exortek/auth').slice(0, 80);
  const rawSub = searchParams.get('desc') || 'Authentication toolkit for Node.js';
  const sub = rawSub.length > 150 ? `${rawSub.slice(0, 147)}…` : rawSub;

  return new ImageResponse(
    <div
      style={{
        height: '100%',
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        background: BG,
        padding: '72px 80px',
        fontFamily: 'sans-serif',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', fontSize: 34, fontWeight: 700 }}>
        <span style={{ color: CREAM }}>@exortek/</span>
        <span style={{ color: GREEN }}>auth</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <div
          style={{
            display: 'flex',
            fontSize: 68,
            fontWeight: 800,
            color: CREAM,
            lineHeight: 1.1,
            letterSpacing: '-0.02em',
          }}
        >
          {heading}
        </div>
        <div
          style={{
            display: 'flex',
            marginTop: 28,
            fontSize: 30,
            color: MUTED,
            lineHeight: 1.35,
            maxWidth: 960,
          }}
        >
          {sub}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', fontSize: 26, color: MUTED }}>
        <span style={{ color: GREEN, marginRight: 14 }}>●</span>
        built on node:crypto · Node.js 22+ · zero-dependency
      </div>
    </div>,
    SIZE,
  );
}
