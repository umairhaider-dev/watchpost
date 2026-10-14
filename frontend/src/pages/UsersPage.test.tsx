import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { UserAccount } from '../api/types';
import { userAccount } from '../test/fixtures';
import { renderAt, type StubRequest, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

interface Captured extends StubRequest {
  path: string;
}

const ADMIN = userAccount({
  id: 1,
  username: 'test.admin',
  full_name: 'Test Admin',
  email: null,
  role: 'admin',
});

function stubUsers(captured: Captured[] = [], replies: Record<string, unknown> = {}) {
  let accounts: UserAccount[] = [userAccount(), ADMIN];
  stubApi((path, _params, request) => {
    if (request.method !== 'GET') captured.push({ ...request, path });
    const key = `${request.method} ${path}`;
    if (key in replies) return replies[key] as { status: number; body?: unknown };
    if (key === 'GET /users') return { status: 200, body: accounts };
    if (key === 'PATCH /users/3') {
      accounts = accounts.map((account) =>
        account.id === 3 ? { ...account, ...(request.body as Partial<UserAccount>) } : account,
      );
      return { status: 200, body: accounts[0] };
    }
    if (key === 'POST /users') {
      const created = userAccount({ id: 4, ...(request.body as Partial<UserAccount>) });
      accounts = [...accounts, created];
      return { status: 201, body: created };
    }
    if (key === 'POST /users/3/password') return { status: 204 };
    return undefined;
  });
}

/** The table row of one account, found by its user name. */
async function rowOf(username: string): Promise<HTMLElement> {
  const table = await screen.findByRole('region', { name: 'Accounts' });
  const name = new RegExp(`^${username.replaceAll('.', '\\.')}`);
  return within(table).findByRole('row', { name });
}

describe('UsersPage', () => {
  it('lists accounts and protects the admin from locking themselves out', async () => {
    stubUsers();
    renderAt('/users');

    const analystRow = await rowOf('analyst.one');
    const adminRow = await rowOf('test.admin');
    expect(within(analystRow).getByText('Analyst One · analyst.one@example.org')).toBeVisible();
    expect(within(analystRow).getByText('2026-10-14 08:30:00 UTC')).toBeInTheDocument();
    expect(within(adminRow).getByText('(you)')).toBeInTheDocument();
    expect(within(adminRow).getByLabelText('Role of test.admin')).toBeDisabled();
    expect(within(adminRow).getByRole('button', { name: 'Deactivate' })).toBeDisabled();
    expect(within(analystRow).getByLabelText('Role of analyst.one')).toBeEnabled();
  });

  it('changes roles and deactivates accounts', async () => {
    const user = userEvent.setup();
    const captured: Captured[] = [];
    stubUsers(captured);
    renderAt('/users');

    const row = await rowOf('analyst.one');
    await user.selectOptions(within(row).getByLabelText('Role of analyst.one'), 'viewer');
    await user.click(within(row).getByRole('button', { name: 'Deactivate' }));

    expect(await screen.findByRole('button', { name: 'Reactivate' })).toBeInTheDocument();
    expect(screen.getByText('Deactivated')).toBeInTheDocument();
    expect(captured.map(({ method, path, body }) => [method, path, body])).toEqual([
      ['PATCH', '/users/3', { role: 'viewer' }],
      ['PATCH', '/users/3', { is_active: false }],
    ]);
  });

  it('adds a user once the name and password are valid', async () => {
    const user = userEvent.setup();
    const captured: Captured[] = [];
    stubUsers(captured);
    renderAt('/users');

    const form = await screen.findByRole('region', { name: 'Add a user' });
    const submit = within(form).getByRole('button', { name: 'Add user' });
    await user.type(within(form).getByLabelText('User name'), 'Viewer.Two');
    await user.type(within(form).getByLabelText('Full name'), 'Viewer Two');
    await user.selectOptions(within(form).getByLabelText('Role'), 'viewer');
    await user.type(within(form).getByLabelText('Initial password'), 'short');
    expect(submit).toBeDisabled();

    await user.type(within(form).getByLabelText('Initial password'), '-but-now-long-enough');
    await user.click(submit);

    expect(await within(form).findByRole('status')).toHaveTextContent('Added viewer.two.');
    expect(captured.map(({ body }) => body)).toEqual([
      {
        username: 'viewer.two',
        password: 'short-but-now-long-enough',
        role: 'viewer',
        full_name: 'Viewer Two',
        email: null,
      },
    ]);
    expect(within(form).getByLabelText('User name')).toHaveValue('');
  });

  it('shows why the API refused a new user', async () => {
    const user = userEvent.setup();
    stubUsers([], {
      'POST /users': {
        status: 409,
        body: { detail: "a user named 'analyst.one' or with that email already exists" },
      },
    });
    renderAt('/users');

    const form = await screen.findByRole('region', { name: 'Add a user' });
    await user.type(within(form).getByLabelText('User name'), 'analyst.one');
    await user.type(within(form).getByLabelText('Initial password'), 'a-long-enough-password');
    await user.click(within(form).getByRole('button', { name: 'Add user' }));

    expect(await within(form).findByRole('alert')).toHaveTextContent('already exists');
  });

  it('resets a password', async () => {
    const user = userEvent.setup();
    const captured: Captured[] = [];
    stubUsers(captured);
    renderAt('/users');

    const row = await rowOf('analyst.one');
    await user.click(within(row).getByRole('button', { name: 'Reset password' }));
    await user.type(screen.getByLabelText('New password for analyst.one'), 'a-fresh-passphrase');
    await user.click(screen.getByRole('button', { name: 'Set password' }));

    expect(await screen.findByRole('status')).toHaveTextContent(
      'New password set for analyst.one; their sessions have been signed out.',
    );
    expect(captured).toEqual([
      {
        method: 'POST',
        path: '/users/3/password',
        body: { password: 'a-fresh-passphrase' },
      },
    ]);
  });
});
