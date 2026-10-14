import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CaseDetail } from '../api/types';
import { analyst, caseDetail, eventRecord } from '../test/fixtures';
import { renderAt, type StubRequest, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

type Reply = { status: number; body?: unknown } | undefined;

const FULL = caseDetail({
  assignee: { id: 3, username: 'analyst.one', full_name: 'Analyst One' },
  assignee_id: 3,
  notes: [
    {
      id: 1,
      body: 'Checked the VPN logs.\nNothing unusual.',
      author: null,
      created_at: '2026-10-12T09:40:00Z',
    },
  ],
  evidence: [
    {
      id: 4,
      note: 'First success after the failures',
      added_by: null,
      created_at: '2026-10-12T09:45:00Z',
      event: eventRecord(2, { user_name: 'backup', message: 'Accepted password for backup' }),
    },
  ],
  activity: [
    {
      id: 1,
      occurred_at: '2026-10-12T09:10:00Z',
      username: null,
      action: 'case.created',
      details: {},
    },
    {
      id: 2,
      occurred_at: '2026-10-12T09:11:00Z',
      username: null,
      action: 'case.alerts_added',
      details: { alert_ids: [11] },
    },
  ],
});

function stubCase(
  detail: CaseDetail = FULL,
  extra: (path: string, request: StubRequest) => Reply = () => undefined,
) {
  return stubApi((path, _params, request) => {
    const special = extra(path, request);
    if (special) return special;
    if (path === '/cases/7' && request.method === 'GET') return { status: 200, body: detail };
    if (path === '/users') return { status: 200, body: [analyst()] };
    return undefined;
  });
}

describe('CasePage', () => {
  it('shows the case with its alerts, evidence, notes and history', async () => {
    stubCase();
    renderAt('/cases/7');

    expect(
      await screen.findByRole('heading', { name: 'SSH brute force on web-01' }),
    ).toBeInTheDocument();
    expect(screen.getByText(/ended in a login as backup/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'SSH brute force: 203.0.113.45' })).toHaveAttribute(
      'href',
      '/alerts/11',
    );
    expect(screen.getByText('First success after the failures')).toBeInTheDocument();
    expect(screen.getByText('Accepted password for backup')).toBeInTheDocument();
    expect(screen.getByText(/Checked the VPN logs/)).toHaveTextContent(
      'Checked the VPN logs. Nothing unusual.',
    );
    expect(screen.getByText(/added alerts #11/)).toBeInTheDocument();
    const entities = screen.getByRole('region', { name: 'Entities' });
    expect(within(entities).getByRole('link', { name: 'root' })).toHaveAttribute(
      'href',
      '/entities/user?value=root',
    );
    expect(screen.getByRole('link', { name: 'PDF' })).toHaveAttribute(
      'href',
      '/api/cases/7/report?format=pdf',
    );
    expect(screen.getByRole('link', { name: 'Markdown' })).toHaveAttribute(
      'href',
      '/api/cases/7/report?format=markdown',
    );
  });

  it('changes status, severity, assignee and resolution', async () => {
    const user = userEvent.setup();
    const sent: unknown[] = [];
    stubCase(FULL, (path, request) => {
      if (path === '/cases/7' && request.method === 'PATCH') {
        sent.push(request.body);
        return { status: 200, body: FULL };
      }
      return undefined;
    });
    renderAt('/cases/7');

    const controls = await screen.findByRole('region', { name: 'Status' });
    await user.selectOptions(within(controls).getByLabelText('Status'), 'resolved');
    await user.selectOptions(within(controls).getByLabelText('Severity'), 'critical');
    await within(controls).findByRole('option', { name: 'Analyst One (analyst.one)' });
    await user.selectOptions(within(controls).getByLabelText('Assignee'), '');
    await user.type(within(controls).getByLabelText('Resolution'), 'Password reset.');
    await user.click(within(controls).getByRole('button', { name: 'Save resolution' }));

    expect(sent).toEqual([
      { status: 'resolved' },
      { severity: 'critical' },
      { assignee_id: null },
      { resolution: 'Password reset.' },
    ]);
  });

  it('adds notes and removes alerts and evidence', async () => {
    const user = userEvent.setup();
    const calls: string[] = [];
    stubCase(FULL, (path, request) => {
      if (request.method === 'GET') return undefined;
      calls.push(`${request.method} ${path}`);
      if (path === '/cases/7/notes') {
        return {
          status: 201,
          body: {
            id: 2,
            body: 'Reset the password',
            author: null,
            created_at: '2026-10-12T10:00:00Z',
          },
        };
      }
      return { status: 204 };
    });
    renderAt('/cases/7');

    const notes = await screen.findByRole('region', { name: 'Notes (1)' });
    await user.type(within(notes).getByLabelText('Add a note'), 'Reset the password');
    await user.click(within(notes).getByRole('button', { name: 'Add note' }));
    await vi.waitFor(() => {
      expect(within(notes).getByLabelText('Add a note')).toHaveValue('');
    });
    await user.click(screen.getByRole('button', { name: 'Remove alert 11 from the case' }));
    await user.click(screen.getByRole('button', { name: 'Unpin event 2' }));

    await vi.waitFor(() => {
      expect(calls).toEqual([
        'POST /cases/7/notes',
        'DELETE /cases/7/alerts/11',
        'DELETE /cases/7/evidence/4',
      ]);
    });
  });

  it('shows errors from the API', async () => {
    const user = userEvent.setup();
    stubCase(FULL, (path, request) =>
      path === '/cases/7' && request.method === 'PATCH'
        ? { status: 422, body: { detail: 'analyst.old is a viewer and cannot be assigned work' } }
        : undefined,
    );
    renderAt('/cases/7');

    const controls = await screen.findByRole('region', { name: 'Status' });
    await user.selectOptions(within(controls).getByLabelText('Status'), 'closed');

    expect(await within(controls).findByRole('alert')).toHaveTextContent('cannot be assigned work');
  });

  it('handles empty, missing and invalid cases', async () => {
    stubCase(caseDetail({ alerts: [], description: '' }));
    const { unmount } = renderAt('/cases/7');
    expect(await screen.findByText(/No alerts yet/)).toBeInTheDocument();
    expect(screen.getByText(/No evidence pinned/)).toBeInTheDocument();
    unmount();

    stubApi(() => ({ status: 404, body: { detail: 'case not found' } }));
    const missing = renderAt('/cases/8');
    expect(await screen.findByText('Could not load this case.')).toBeInTheDocument();
    missing.unmount();

    renderAt('/cases/abc');
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});
