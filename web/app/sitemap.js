const SITE_URL = 'https://auth.memet.dev';

// Top-level routes plus the multi-page package sections. Kept explicit so the
// sitemap stays correct regardless of how Nextra resolves the page map.
const ROUTES = [
  '',
  'guides',
  'guides/password-login',
  'guides/jwt-access-refresh',
  'guides/two-factor',
  'guides/magic-link',
  'guides/api-keys',
  'comparison',
  'compliance',
  'crypto',
  'password',
  'otp',
  'challenge',
  'jwk',
  'jws',
  'jws/sign',
  'jws/verify',
  'jws/decode',
  'jws/json',
  'jws/errors',
  'jwt',
  'jwt/sign',
  'jwt/verify',
  'jwt/token-pair',
  'jwt/stores',
  'jwt/errors',
  'jwe',
  'jwe/encrypt',
  'jwe/decrypt',
  'jwe/decode',
  'jwe/json',
  'jwe/algorithms',
  'jwe/errors',
  'jwks',
  'session',
  'security',
  'ua',
  'apikey',
  'magic-link',
  'passkey',
  'opaque',
];

export default function sitemap() {
  const lastModified = new Date();
  return ROUTES.map(route => ({
    url: route ? `${SITE_URL}/${route}` : SITE_URL,
    lastModified,
    changeFrequency: 'weekly',
    priority: route === '' ? 1 : 0.7,
  }));
}
