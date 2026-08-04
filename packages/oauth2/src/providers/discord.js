/**
 * Discord — OAuth 2.0 provider. Identity comes from `GET /users/@me`.
 *
 * @example
 * import { discord } from '@exortek/oauth2/providers/discord';
 * discord({ clientId, clientSecret });
 */
import { defineProvider } from './_base.js';

export const discord = defineProvider({
  id: 'discord',
  kind: 'oauth2',
  authorizationEndpoint: 'https://discord.com/oauth2/authorize',
  tokenEndpoint: 'https://discord.com/api/oauth2/token',
  revocationEndpoint: 'https://discord.com/api/oauth2/token/revoke',
  userinfoEndpoint: 'https://discord.com/api/users/@me',
  defaultScopes: ['identify', 'email'],
  mapUser: raw => ({
    sub: String(raw.id),
    email: raw.email,
    emailVerified: raw.verified,
    name: raw.global_name ?? raw.username,
    picture: raw.avatar ? `https://cdn.discordapp.com/avatars/${raw.id}/${raw.avatar}.png` : undefined,
  }),
});
