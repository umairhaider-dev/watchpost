import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { renderAt, requestUrl, type StubRequest, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

const NEW_PASSWORD = 'a-much-longer-passphrase';

describe('AccountPage', () => {
  it('shows the profile and role', async () => {
    stubApi(() => undefined);
    renderAt('/account');

    const profile = await screen.findByRole('region', { name: 'Profile' });
    expect(within(profile).getByText('test.admin')).toBeInTheDocument();
    expect(within(profile).getByText('Test Admin')).toBeInTheDocument();
    expect(within(profile).getByText('Admin')).toBeInTheDocument();
  });

  it('changes the password once both entries match', async () => {
    const user = userEvent.setup();
    const sent: StubRequest[] = [];
    let attempts = 0;
    stubApi((path, _params, request) => {
      if (path !== '/auth/password') return undefined;
      sent.push(request);
      attempts += 1;
      return attempts === 1
        ? { status: 400, body: { detail: 'the current password is wrong' } }
        : {
            status: 200,
            body: {
              user: { id: 1, username: 'test.admin', full_name: null, email: null, role: 'admin' },
              expires_at: '2026-10-14T18:00:00Z',
            },
          };
    });
    renderAt('/account');

    const form = await screen.findByRole('region', { name: 'Change password' });
    const submit = within(form).getByRole('button', { name: 'Change password' });
    await user.type(within(form).getByLabelText('Current password'), 'old-password');
    await user.type(within(form).getByLabelText('New password'), NEW_PASSWORD);
    await user.type(within(form).getByLabelText('New password again'), 'something else');
    expect(within(form).getByText('The passwords do not match.')).toBeInTheDocument();
    expect(submit).toBeDisabled();

    await user.clear(within(form).getByLabelText('New password again'));
    await user.type(within(form).getByLabelText('New password again'), NEW_PASSWORD);
    await user.click(submit);
    expect(await within(form).findByRole('alert')).toHaveTextContent(
      'the current password is wrong',
    );

    await user.click(submit);
    expect(await within(form).findByRole('status')).toHaveTextContent('Password changed.');
    expect(sent.map((request) => request.body)).toEqual([
      { current_password: 'old-password', new_password: NEW_PASSWORD },
      { current_password: 'old-password', new_password: NEW_PASSWORD },
    ]);
    expect(within(form).getByLabelText('Current password')).toHaveValue('');
  });

  it('refuses short new passwords before asking the API', async () => {
    const user = userEvent.setup();
    stubApi(() => undefined);
    renderAt('/account');

    const form = await screen.findByRole('region', { name: 'Change password' });
    await user.type(within(form).getByLabelText('Current password'), 'old-password');
    await user.type(within(form).getByLabelText('New password'), 'short');
    await user.type(within(form).getByLabelText('New password again'), 'short');

    expect(within(form).getByRole('button', { name: 'Change password' })).toBeDisabled();
  });

  it('signs out everywhere', async () => {
    const fetchMock = stubApi((path) => (path === '/auth/logout' ? { status: 204 } : undefined));
    renderAt('/account');

    await userEvent
      .setup()
      .click(await screen.findByRole('button', { name: 'Sign out everywhere' }));

    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    const logouts = fetchMock.mock.calls
      .map(([input]) => requestUrl(input))
      .filter((url) => url.pathname === '/api/auth/logout');
    expect(logouts.map((url) => url.search)).toEqual(['?everywhere=true']);
  });
});
