import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { auditEntry } from '../test/fixtures';
import { renderAt, requestUrl, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

const ENTRIES = [
  auditEntry(),
  auditEntry({
    id: 2,
    username: 'root',
    user_id: null,
    action: 'auth.login_failed',
    target_type: 'user',
    target_id: 'root',
    ip_address: '203.0.113.45',
  }),
  auditEntry({
    id: 3,
    action: 'user.updated',
    target_type: 'user',
    target_id: '3',
    details: { role: { from: 'analyst', to: 'admin' } },
  }),
];

function lastAuditQuery(fetchMock: ReturnType<typeof stubApi>): URLSearchParams {
  const urls = fetchMock.mock.calls
    .map(([input]) => requestUrl(input))
    .filter((url) => url.pathname === '/api/audit');
  return urls.at(-1)?.searchParams ?? new URLSearchParams();
}

describe('AuditPage', () => {
  it('lists entries in plain words', async () => {
    stubApi((path) =>
      path === '/audit' ? { status: 200, body: { items: ENTRIES, total: 3 } } : undefined,
    );
    renderAt('/audit');

    expect(await screen.findByText('Disabled a rule')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'rule ssh-brute-force' })).toHaveAttribute(
      'href',
      '/rules/ssh-brute-force',
    );
    expect(screen.getByText('Failed sign-in')).toHaveClass('text-error');
    expect(screen.getByText('203.0.113.45')).toBeInTheDocument();
    expect(screen.getByText('role: analyst → admin')).toBeInTheDocument();
    expect(screen.getByText('1–3 of 3')).toBeInTheDocument();
  });

  it('filters by area and user and pages through results', async () => {
    const user = userEvent.setup();
    const fetchMock = stubApi((path) =>
      path === '/audit' ? { status: 200, body: { items: ENTRIES, total: 120 } } : undefined,
    );
    renderAt('/audit');
    const card = await screen.findByRole('region', { name: 'Entries' });
    await within(card).findByText('Disabled a rule');

    await user.selectOptions(within(card).getByLabelText('Area'), 'auth.');
    expect(lastAuditQuery(fetchMock).get('action')).toBe('auth.');

    await user.type(within(card).getByLabelText('User'), 'root{Enter}');
    expect(lastAuditQuery(fetchMock).get('username')).toBe('root');

    await user.click(within(card).getByRole('button', { name: 'Older' }));
    expect(lastAuditQuery(fetchMock).get('offset')).toBe('50');
    expect(await within(card).findByText('51–100 of 120')).toBeInTheDocument();

    await user.click(within(card).getByRole('button', { name: 'Clear' }));
    const params = lastAuditQuery(fetchMock);
    expect([params.get('username'), params.get('offset'), params.get('action')]).toEqual([
      null,
      '0',
      'auth.',
    ]);
  });

  it('narrows to one user from the table', async () => {
    const user = userEvent.setup();
    const fetchMock = stubApi((path) =>
      path === '/audit' ? { status: 200, body: { items: ENTRIES, total: 3 } } : undefined,
    );
    renderAt('/audit');

    await user.click(await screen.findByRole('button', { name: 'root' }));

    expect(lastAuditQuery(fetchMock).get('username')).toBe('root');
    expect(screen.getByLabelText('User')).toHaveValue('root');
  });
});
