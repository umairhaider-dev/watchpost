import { describe, expect, it } from 'vitest';

import { roleAllows } from '../api/auth';
import { isValidPassword, isValidUsername, returnPath } from './accounts';

describe('returnPath', () => {
  it.each([
    [{ from: '/cases/7?tab=notes' }, '/cases/7?tab=notes'],
    [{ from: '/' }, '/'],
    [{ from: '//evil.example/path' }, '/'],
    [{ from: '/\\evil.example' }, '/'],
    [{ from: 'https://evil.example' }, '/'],
    [{ from: '/login' }, '/'],
    [{ from: 42 }, '/'],
    [null, '/'],
    ['/alerts', '/'],
  ])('maps %o to %s', (state, expected) => {
    expect(returnPath(state)).toBe(expected);
  });
});

describe('account rules', () => {
  it('match the API username pattern', () => {
    expect(isValidUsername('analyst.one')).toBe(true);
    expect(isValidUsername('a_b-c.d')).toBe(true);
    expect(isValidUsername('ab')).toBe(false);
    expect(isValidUsername('Analyst')).toBe(false);
    expect(isValidUsername('.hidden')).toBe(false);
    expect(isValidUsername('x'.repeat(65))).toBe(false);
  });

  it('match the API password length limits', () => {
    expect(isValidPassword('x'.repeat(11))).toBe(false);
    expect(isValidPassword('x'.repeat(12))).toBe(true);
    expect(isValidPassword('x'.repeat(257))).toBe(false);
  });

  it('rank roles', () => {
    expect(roleAllows('admin', 'analyst')).toBe(true);
    expect(roleAllows('analyst', 'analyst')).toBe(true);
    expect(roleAllows('viewer', 'analyst')).toBe(false);
    expect(roleAllows('analyst', 'admin')).toBe(false);
  });
});
