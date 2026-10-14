import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { alertSummary, analyst, caseDetail, caseSummary } from '../test/fixtures';
import { renderAt, requestUrl, type StubRequest, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

type Reply = { status: number; body?: unknown } | undefined;

function stubQueue(extra: (path: string, request: StubRequest) => Reply = () => undefined) {
  return stubApi((path, _params, request) => {
    const special = extra(path, request);
    if (special) return special;
    if (path === '/alerts') {
      return {
        status: 200,
        body: {
          items: [
            alertSummary(),
            alertSummary({
              id: 12,
              title: 'LSASS process memory accessed',
              severity: 'critical',
              host_name: 'ws-fin-07',
              source_ip: null,
              user_name: 'carol',
              assignee_id: 3,
              case_id: 7,
            }),
          ],
          total: 2,
        },
      };
    }
    if (path === '/users') return { status: 200, body: [analyst()] };
    if (path === '/cases') return { status: 200, body: { items: [caseSummary()], total: 1 } };
    return undefined;
  });
}

function lastAlertQuery(fetchMock: ReturnType<typeof stubApi>): URLSearchParams {
  const urls = fetchMock.mock.calls
    .map(([input]) => requestUrl(input))
    .filter((url) => url.pathname === '/api/alerts');
  return urls.at(-1)?.searchParams ?? new URLSearchParams();
}

describe('AlertsPage', () => {
  it('lists alerts with entity links, owners and cases', async () => {
    stubQueue();
    renderAt('/alerts');

    const link = await screen.findByRole('link', { name: 'SSH brute force: 203.0.113.45' });
    expect(link).toHaveAttribute('href', '/alerts/11');
    expect(screen.getByRole('link', { name: 'ws-fin-07' })).toHaveAttribute(
      'href',
      '/entities/host?value=ws-fin-07',
    );
    expect(screen.getByRole('link', { name: '203.0.113.45' })).toHaveAttribute(
      'href',
      '/entities/ip?value=203.0.113.45',
    );
    expect(await screen.findByRole('cell', { name: 'analyst.one' })).toBeInTheDocument();
    expect(screen.getByText(/#12 · T1110\.001 · case #7/)).toBeInTheDocument();
    expect(screen.getByText('Alert queue').nextSibling).toHaveTextContent('2');
  });

  it('sends every filter to the API', async () => {
    const user = userEvent.setup();
    const fetchMock = stubQueue();
    renderAt('/alerts?rule=ssh-brute-force&technique=T1110.001');
    await screen.findByText('Alerts from ssh-brute-force');

    await user.click(screen.getByRole('button', { name: 'critical' }));
    await user.click(screen.getByRole('button', { name: 'New' }));
    await user.type(screen.getByLabelText('Host'), 'web-01');
    await user.type(screen.getByLabelText('Source IP'), '203.0.113.45');
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    await user.selectOptions(screen.getByLabelText('Active in'), '24h');
    await user.selectOptions(screen.getByLabelText('Assignee'), 'none');
    await user.selectOptions(screen.getByLabelText('Sort by'), 'severity');

    const params = lastAlertQuery(fetchMock);
    expect(params.getAll('severity')).toEqual(['critical']);
    expect(params.getAll('status')).toEqual(['new']);
    expect(params.get('rule_id')).toBe('ssh-brute-force');
    expect(params.get('technique')).toBe('T1110.001');
    expect(params.get('host')).toBe('web-01');
    expect(params.get('source_ip')).toBe('203.0.113.45');
    expect(params.get('unassigned')).toBe('true');
    expect(params.get('sort')).toBe('severity');
    const since = Date.parse(params.get('since') ?? '');
    expect(Date.now() - since).toBeGreaterThan(23 * 3_600_000);

    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    const cleared = lastAlertQuery(fetchMock);
    expect(cleared.get('rule_id')).toBeNull();
    expect(cleared.getAll('severity')).toEqual([]);
    expect(screen.getByLabelText('Host')).toHaveValue('');
  });

  it('updates the status of selected alerts in bulk', async () => {
    const user = userEvent.setup();
    const sent: unknown[] = [];
    stubQueue((path, request) => {
      if (path !== '/alerts/bulk') return undefined;
      sent.push(request.body);
      return {
        status: 200,
        body: {
          updated: [11],
          unchanged: [],
          missing: [],
          conflicts: [{ alert_id: 12, open_alert_id: 30 }],
        },
      };
    });
    renderAt('/alerts');

    await user.click(await screen.findByLabelText('Select all alerts'));
    const bar = screen.getByLabelText('Bulk actions');
    expect(within(bar).getByText('2 selected')).toBeInTheDocument();
    await user.selectOptions(within(bar).getByLabelText('Set status'), 'false_positive');
    await user.click(within(bar).getByRole('button', { name: 'Apply' }));

    expect(sent).toEqual([{ alert_ids: [11, 12], status: 'false_positive' }]);
    expect(screen.queryByLabelText('Bulk actions')).not.toBeInTheDocument();
  });

  it('opens a case from selected alerts', async () => {
    const user = userEvent.setup();
    const sent: unknown[] = [];
    stubQueue((path, request) => {
      if (path === '/cases' && request.method === 'POST') {
        sent.push(request.body);
        return { status: 201, body: caseDetail({ id: 9 }) };
      }
      return undefined;
    });
    renderAt('/alerts');

    await user.click(await screen.findByLabelText('Select alert 11'));
    const form = screen.getByRole('form', { name: 'Add to case' });
    await user.type(within(form).getByLabelText('Title'), 'Brute force on web-01');
    await user.click(within(form).getByRole('button', { name: 'Open case' }));

    expect(sent).toEqual([{ title: 'Brute force on web-01', alert_ids: [11] }]);
  });

  it('adds selected alerts to an existing case', async () => {
    const user = userEvent.setup();
    const sent: StubRequest[] = [];
    stubQueue((path, request) => {
      if (path === '/cases/7/alerts') {
        sent.push(request);
        return { status: 200, body: { added: [11] } };
      }
      return undefined;
    });
    renderAt('/alerts');

    await user.click(await screen.findByLabelText('Select alert 11'));
    const form = screen.getByRole('form', { name: 'Add to case' });
    await user.selectOptions(within(form).getByLabelText('Case'), '7');
    await user.click(within(form).getByRole('button', { name: 'Add to case' }));

    expect(sent.map((request) => request.body)).toEqual([{ alert_ids: [11] }]);
  });

  it('says when nothing matches or loading fails', async () => {
    stubApi((path) => (path === '/alerts' ? { status: 500, body: { detail: 'boom' } } : undefined));
    renderAt('/alerts');

    expect(await screen.findByText('Could not load alerts.')).toBeInTheDocument();
  });
});
