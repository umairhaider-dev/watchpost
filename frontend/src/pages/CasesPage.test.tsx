import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { analyst, caseDetail, caseSummary } from '../test/fixtures';
import { renderAt, requestUrl, type StubRequest, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

function lastCasesQuery(fetchMock: ReturnType<typeof stubApi>): URLSearchParams {
  const urls = fetchMock.mock.calls
    .map(([input]) => requestUrl(input))
    .filter((url) => url.pathname === '/api/cases');
  return urls.at(-1)?.searchParams ?? new URLSearchParams();
}

describe('CasesPage', () => {
  it('lists active cases and filters them', async () => {
    const user = userEvent.setup();
    const fetchMock = stubApi((path, _params, request) => {
      if (path === '/cases' && request.method === 'GET') {
        return {
          status: 200,
          body: {
            items: [caseSummary({ assignee_id: 3, open_alert_count: 1, alert_count: 2 })],
            total: 1,
          },
        };
      }
      if (path === '/users') return { status: 200, body: [analyst()] };
      return undefined;
    });
    renderAt('/cases');

    const link = await screen.findByRole('link', { name: 'SSH brute force on web-01' });
    expect(link).toHaveAttribute('href', '/cases/7');
    expect(await screen.findByRole('cell', { name: 'analyst.one' })).toBeInTheDocument();
    expect(screen.getByRole('cell', { name: '1/2' })).toBeInTheDocument();
    expect(lastCasesQuery(fetchMock).getAll('status')).toEqual(['open', 'in_progress']);

    const table = screen.getByRole('region', { name: 'Cases' });
    await user.selectOptions(within(table).getByLabelText('Status'), 'closed');
    await user.selectOptions(within(table).getByLabelText('Assignee'), '3');
    await user.type(within(table).getByLabelText('Search case titles'), 'ssh');

    const params = lastCasesQuery(fetchMock);
    expect(params.getAll('status')).toEqual(['closed']);
    expect(params.get('assignee_id')).toBe('3');
    expect(params.get('q')).toBe('ssh');
  });

  it('opens a new case and goes to it', async () => {
    const user = userEvent.setup();
    const sent: StubRequest[] = [];
    stubApi((path, _params, request) => {
      if (path === '/cases' && request.method === 'POST') {
        sent.push(request);
        return { status: 201, body: caseDetail({ id: 9, title: 'Phishing wave' }) };
      }
      if (path === '/cases') return { status: 200, body: { items: [], total: 0 } };
      if (path === '/cases/9')
        return { status: 200, body: caseDetail({ id: 9, title: 'Phishing wave' }) };
      return undefined;
    });
    renderAt('/cases');

    const form = await screen.findByRole('region', { name: 'Open a case' });
    await user.type(within(form).getByLabelText('Title'), 'Phishing wave');
    await user.selectOptions(within(form).getByLabelText('Severity'), 'high');
    await user.type(within(form).getByLabelText('Description'), 'Several invoices');
    await user.click(within(form).getByRole('button', { name: 'Open case' }));

    expect(await screen.findByRole('heading', { name: 'Phishing wave' })).toBeInTheDocument();
    expect(sent.map((request) => request.body)).toEqual([
      { title: 'Phishing wave', severity: 'high', description: 'Several invoices' },
    ]);
  });
});
