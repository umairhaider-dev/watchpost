// Account rules, kept in step with watchpost.core.passwords and watchpost.accounts.

export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 256;

const USERNAME = /^[a-z0-9][a-z0-9._-]{2,63}$/;

export const USERNAME_RULE =
  '3 to 64 characters: lowercase letters, digits, dots, dashes and underscores.';

export function isValidUsername(name: string): boolean {
  return USERNAME.test(name);
}

export function isValidPassword(password: string): boolean {
  return password.length >= MIN_PASSWORD_LENGTH && password.length <= MAX_PASSWORD_LENGTH;
}

/** The in-app path to return to after signing in; anything else falls back to "/". */
export function returnPath(state: unknown): string {
  if (typeof state !== 'object' || state === null || !('from' in state)) return '/';
  const { from } = state;
  // "//host" and "/\host" would leave the site, so only plain absolute paths pass.
  if (typeof from !== 'string' || !/^\/(?![/\\])/.test(from)) return '/';
  return from.startsWith('/login') ? '/' : from;
}
