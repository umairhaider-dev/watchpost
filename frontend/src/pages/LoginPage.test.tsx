import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { signedInAs } from '../test/fixtures';
import { renderAt, signedInAdmin, type StubRequest, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

const SIGNED_IN = { user: signedInAdmin, expires_at: '2026-10-14T18:00:00Z' };

async function fillIn(name: string, password: string) {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText('User name'), name);
  await user.type(screen.getByLabelText('Password'), password);
  await user.click(screen.getByRole('button', { name: 'Sign in' }));
}

describe('signing in', () => {
  it('sends visitors to the sign-in page and back to where they were going', async () => {
    const sent: StubRequest[] = [];
    stubApi(
      (path, _params, request) => {
        if (path === '/auth/login') {
          sent.push(request);
          return { status: 200, body: SIGNED_IN };
        }
        if (path === '/cases') return { status: 200, body: { items: [], total: 0 } };
        return undefined;
      },
      { user: null },
    );
    renderAt('/cases');

    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    await fillIn(' test.admin ', 'correct-horse-battery');

    expect(await screen.findByRole('heading', { name: 'Cases', level: 1 })).toBeInTheDocument();
    expect(sent.map((request) => request.body)).toEqual([
      { username: 'test.admin', password: 'correct-horse-battery' },
    ]);
    expect(screen.getByRole('link', { name: /Test Admin/ })).toHaveAttribute('href', '/account');
  });

  it('explains wrong credentials and throttling', async () => {
    let attempts = 0;
    stubApi(
      (path) => {
        if (path !== '/auth/login') return undefined;
        attempts += 1;
        return attempts === 1
          ? { status: 401, body: { detail: 'wrong user name or password' } }
          : {
              status: 429,
              body: { detail: 'too many failed sign-ins; try again later' },
              headers: { 'Retry-After': '540' },
            };
      },
      { user: null },
    );
    renderAt('/login');

    await fillIn('analyst.one', 'nope');
    expect(await screen.findByRole('alert')).toHaveTextContent('Wrong user name or password.');

    await userEvent.setup().click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText(/Too many failed sign-ins/)).toHaveTextContent(
      'Too many failed sign-ins. Try again in 9 minutes.',
    );
  });

  it('skips the form for someone already signed in', async () => {
    stubApi(() => undefined);
    renderAt('/login');

    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
  });
});

describe('sessions', () => {
  it('signs out from the sidebar', async () => {
    const sent: string[] = [];
    stubApi((path, _params, request) => {
      if (path === '/auth/logout') {
        sent.push(request.method);
        return { status: 204 };
      }
      return undefined;
    });
    renderAt('/schema');

    await userEvent.setup().click(await screen.findByRole('button', { name: 'Sign out' }));

    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(sent).toEqual(['POST']);
  });

  it('returns to the sign-in page when the session ends', async () => {
    stubApi((path) =>
      path === '/cases' ? { status: 401, body: { detail: 'sign in first' } } : undefined,
    );
    renderAt('/cases');

    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
  });

  it('offers a retry when the API cannot be reached', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response('Bad gateway', { status: 502 }))),
    );
    renderAt('/');

    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('Could not reach the Watchpost API.')).toBeInTheDocument();
    expect(within(alert).getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });
});

describe('roles', () => {
  it('shows administration only to admins', async () => {
    stubApi(() => undefined);
    renderAt('/schema');

    expect(await screen.findByRole('link', { name: 'Users' })).toHaveAttribute('href', '/users');
    expect(screen.getByRole('link', { name: 'Audit log' })).toHaveAttribute('href', '/audit');
    expect(screen.queryByRole('note')).not.toBeInTheDocument();
  });

  it('keeps analysts out of the admin pages', async () => {
    stubApi(() => undefined, { user: signedInAs('analyst') });
    renderAt('/users');

    expect(await screen.findByRole('heading', { name: 'Admins only' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Users' })).not.toBeInTheDocument();
    expect(screen.queryByRole('note')).not.toBeInTheDocument();
  });

  it('tells viewers their access is read-only', async () => {
    stubApi(() => undefined, { user: signedInAs('viewer') });
    renderAt('/schema');

    expect(await screen.findByRole('note')).toHaveTextContent('You have read-only access.');
    expect(screen.getByText('viewer.one · Viewer')).toBeInTheDocument();
  });
});
