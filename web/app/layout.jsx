import { Footer, Layout, Navbar } from 'nextra-theme-docs';
import { Head } from 'nextra/components';
import { getPageMap } from 'nextra/page-map';
import 'nextra-theme-docs/style.css';
import './home.css';

const SITE_URL = 'https://auth.memet.dev';
const DESCRIPTION =
  'Framework-agnostic, zero-dependency authentication primitives for Node.js 22+ — password hashing, OTP, sessions, passkeys, API keys, and the full RFC-compliant JOSE stack (JWK/JWS/JWT/JWE/JWKS). Built on node:crypto.';

export const metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: '@exortek/auth — authentication toolkit for Node.js',
    template: '%s — @exortek/auth',
  },
  description: DESCRIPTION,
  applicationName: '@exortek/auth',
  keywords: [
    'authentication',
    'node.js',
    'jwt',
    'jwe',
    'jws',
    'jwk',
    'jwks',
    'jose',
    'passkey',
    'webauthn',
    'fido2',
    'otp',
    'totp',
    'password hashing',
    'argon2',
    'session',
    'csrf',
    'api keys',
    'magic link',
    'node:crypto',
    'zero-dependency',
  ],
  authors: [{ name: 'ExorTek', url: 'https://github.com/ExorTek' }],
  alternates: { canonical: '/' },
  openGraph: {
    type: 'website',
    siteName: '@exortek/auth',
    title: '@exortek/auth — authentication toolkit for Node.js',
    description: DESCRIPTION,
    url: SITE_URL,
    locale: 'en_US',
  },
  twitter: {
    card: 'summary_large_image',
    title: '@exortek/auth — authentication toolkit for Node.js',
    description: DESCRIPTION,
  },
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, 'max-image-preview': 'large', 'max-snippet': -1 },
  },
};

const logo = (
  <span style={{ fontWeight: 700, letterSpacing: '-0.01em' }}>
    @exortek/<span style={{ color: '#12b76a' }}>auth</span>
  </span>
);

const navbar = <Navbar logo={logo} projectLink="https://github.com/ExorTek/auth" />;

const footer = (
  <Footer>
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', width: '100%' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1.25rem', fontSize: '0.875rem' }}>
        <a href="/guides">Guides</a>
        <a href="/compliance">Compliance</a>
        <a href="https://github.com/ExorTek/auth">GitHub</a>
        <a href="https://www.npmjs.com/org/exortek">npm</a>
        <a href="https://github.com/ExorTek/auth/blob/master/CONTRIBUTING.md">Contributing</a>
      </div>
      <div style={{ opacity: 0.7 }}>MIT © {new Date().getFullYear()} · @exortek/auth — built on node:crypto</div>
    </div>
  </Footer>
);

export default async function RootLayout({ children }) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <Head color={{ hue: 152, saturation: 58 }} />
      <body>
        <Layout
          navbar={navbar}
          footer={footer}
          pageMap={await getPageMap()}
          docsRepositoryBase="https://github.com/ExorTek/auth/tree/master/web"
          sidebar={{ defaultMenuCollapseLevel: 1 }}
        >
          {children}
        </Layout>
      </body>
    </html>
  );
}
