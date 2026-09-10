import { ImageResponse } from 'next/og';

// Apple touch icon. Generated (rather than a static file) so it stays in sync
// with the brand mark in icon.svg; the apple-icon convention wants a raster
// type, so we render one at the standard 180×180.
export const size = { width: 180, height: 180 };
export const contentType = 'image/png';

export default function appleIcon() {
  return new ImageResponse(
    <div
      style={{
        height: '100%',
        width: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#17181c',
        color: '#e4dcc7',
        fontSize: 116,
        fontWeight: 700,
        fontFamily: 'monospace',
      }}
    >
      @
    </div>,
    size,
  );
}
