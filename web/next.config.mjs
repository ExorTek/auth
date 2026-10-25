import nextra from 'nextra';

const withNextra = nextra({
  defaultShowCopyCode: true,
  search: {
    codeblocks: false,
  },
  mdxOptions: {
    rehypePrettyCodeOptions: {
      theme: {
        light: 'one-light',
        dark: 'one-dark-pro',
      },
    },
  },
});

// Cloudflare already adds HSTS and `X-Content-Type-Options` at the edge. The
// CSP carries only directives that cannot break Next's inline hydration
// scripts or the analytics beacon: no framing, no <base> hijack, no plugins,
// forms post only to this origin.
const SECURITY_HEADERS = [
  {
    key: 'Content-Security-Policy',
    value: "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'",
  },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async headers() {
    return [{ source: '/:path*', headers: SECURITY_HEADERS }];
  },
};

export default withNextra(nextConfig);
