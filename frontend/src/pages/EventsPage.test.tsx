import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { EventRecord } from '../api/types';
import { caseSummary } from '../test/fixtures';
import { renderAt, requestUrl, type StubRequest, stubApi } from '../test/utils';

function event(id: number, overrides: Partial<EventRecord> = {}): EventRecord {
  return {
    id,
    timestamp: '2026-10-12T09:02:13Z',
    ingested_at: '2026-10-13T08:00:00Z',
    log_source: 'linux_auth',
    host_name: 'web-01',
    source_ip: '203.0.113.45',
    source_port: 40112,
    destination_ip: null,
    destination_port: null,
    user_name: 'root',
    event_category: 'authentication',
    event_action: 'ssh_login',
    event_outcome: 'failure',
    event_code: null,
    process_name: 'sshd',
    process_pid: 3101,
    process_executable: null,
    process_command_line: null,
    process_parent_name: null,
    process_parent_pid: null,
    url_original: null,
    http_method: null,
    http_status_code: null,
    user_agent: null,
    message: 'Failed password for root from 203.0.113.45 port 40112 ssh2',
    ioc_matched: false,
    raw_event: { line: `raw line ${String(id)}` },
    ...overrides,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('EventsPage', () => {
  it('lists events and shows the raw record when a row is expanded', async () => {
    const user = userEvent.setup();
    stubApi((path) =>
      path === '/events'
        ? { status: 200, body: { items: [event(1)], next_cursor: null } }
        : undefined,
    );
    renderAt('/events');

    const toggle = await screen.findByRole('button', { name: /2026-10-12 09:02:13 UTC/ });
    expect(screen.getByText('ssh_login')).toHaveAttribute('data-outcome', 'failure');
    expect(screen.getByText('203.0.113.45')).toBeInTheDocument();

    await user.click(toggle);

    expect(await screen.findByText(/"line": "raw line 1"/)).toBeInTheDocument();
    expect(screen.getByText('2026-10-13 08:00:00 UTC')).toBeInTheDocument();
  });

  it('filters by log source and loads older pages', async () => {
    const user = userEvent.setup();
    const fetchMock = stubApi((path, params) => {
      if (path !== '/events') return undefined;
      if (params.get('cursor') === 'page2') {
        return { status: 200, body: { items: [event(3)], next_cursor: null } };
      }
      return {
        status: 200,
        body: {
          items: [
            event(2, {
              log_source: (params.get('log_source') ?? 'linux_auth') as EventRecord['log_source'],
            }),
          ],
          next_cursor: 'page2',
        },
      };
    });
    renderAt('/events');
    await screen.findByText('linux_auth');

    await user.selectOptions(screen.getByLabelText('Source'), 'sysmon');
    expect(await screen.findByText('sysmon')).toBeInTheDocument();
    const requested = fetchMock.mock.calls.map(([input]) => requestUrl(input).href);
    expect(requested.some((url) => url.includes('log_source=sysmon'))).toBe(true);

    await user.click(screen.getByRole('button', { name: 'Load older events' }));
    expect(await screen.findAllByRole('button', { name: /UTC/ })).toHaveLength(2);
    expect(screen.queryByRole('button', { name: 'Load older events' })).not.toBeInTheDocument();
  });

  it('summarises web and process events', async () => {
    stubApi((path) =>
      path === '/events'
        ? {
            status: 200,
            body: {
              items: [
                event(4, {
                  log_source: 'web_access',
                  url_original: '/products?id=1',
                  http_method: 'GET',
                  http_status_code: 500,
                }),
                event(5, {
                  log_source: 'sysmon',
                  process_command_line: 'powershell.exe -enc SQBFAFgA',
                }),
              ],
              next_cursor: null,
            },
          }
        : undefined,
    );
    renderAt('/events');

    expect(await screen.findByText('GET /products?id=1 500')).toBeInTheDocument();
    expect(screen.getByText('powershell.exe -enc SQBFAFgA')).toBeInTheDocument();
  });

  it('says when there is nothing to show', async () => {
    stubApi((path) =>
      path === '/events' ? { status: 200, body: { items: [], next_cursor: null } } : undefined,
    );
    renderAt('/events');

    expect(await screen.findByText(/No events yet/)).toBeInTheDocument();
  });
});

describe('EventsPage threat intel matches', () => {
  const MATCHED = event(2, { ioc_matched: true });

  it('flags matched events, filters to them and lists the indicators', async () => {
    const user = userEvent.setup();
    const fetchMock = stubApi((path, params) => {
      if (path === '/events') {
        const items = params.get('ioc_matched') === 'true' ? [MATCHED] : [event(1), MATCHED];
        return { status: 200, body: { items, next_cursor: null } };
      }
      if (path === '/events/2/indicators') {
        return {
          status: 200,
          body: [
            {
              ioc_id: 1,
              ioc_type: 'ip',
              value: '203.0.113.45',
              field: 'source.ip',
              source: 'iocs.csv',
              description: 'SSH brute-force source',
              confidence: 85,
              tags: ['ssh'],
              is_active: true,
            },
          ],
        };
      }
      return undefined;
    });
    renderAt('/events');

    expect(await screen.findAllByRole('button', { name: /2026-10-12/ })).toHaveLength(2);
    expect(screen.getAllByTitle('Matched a threat indicator')).toHaveLength(1);

    await user.click(screen.getByRole('button', { name: 'Threat intel matches' }));

    await vi.waitFor(() => {
      expect(screen.getAllByRole('button', { name: /2026-10-12/ })).toHaveLength(1);
    });
    const lastUrl = requestUrl(fetchMock.mock.calls.at(-1)?.[0]);
    expect(lastUrl.searchParams.get('ioc_matched')).toBe('true');

    await user.click(screen.getByRole('button', { name: /2026-10-12/ }));
    const heading = await screen.findByRole('heading', { name: 'Threat intel matches' });
    const list = heading.nextElementSibling as HTMLElement;
    expect(await within(list).findByText('203.0.113.45')).toBeInTheDocument();
    expect(within(list).getByText(/in source\.ip · iocs\.csv · confidence 85/)).toBeInTheDocument();
    expect(within(list).getByText('SSH brute-force source')).toBeInTheDocument();
  });

  it('explains an empty filtered list', async () => {
    const user = userEvent.setup();
    stubApi((path, params) =>
      path === '/events'
        ? {
            status: 200,
            body: { items: params.get('ioc_matched') ? [] : [event(1)], next_cursor: null },
          }
        : undefined,
    );
    renderAt('/events');
    await screen.findByRole('button', { name: /2026-10-12/ });

    await user.click(screen.getByRole('button', { name: 'Threat intel matches' }));

    expect(await screen.findByText('No events match this search.')).toBeInTheDocument();
  });
});

describe('EventsPage search', () => {
  function lastSearch(fetchMock: ReturnType<typeof stubApi>): URLSearchParams {
    const urls = fetchMock.mock.calls
      .map(([input]) => requestUrl(input))
      .filter((url) => url.pathname === '/api/events');
    return urls.at(-1)?.searchParams ?? new URLSearchParams();
  }

  it('runs a query and a time range from the search box', async () => {
    const user = userEvent.setup();
    const fetchMock = stubApi((path) =>
      path === '/events'
        ? { status: 200, body: { items: [event(1)], next_cursor: null } }
        : undefined,
    );
    renderAt('/events');
    await screen.findByRole('button', { name: /2026-10-12/ });

    await user.type(screen.getByLabelText('Query'), 'user.name:root AND event.outcome:failure');
    await user.click(screen.getByRole('button', { name: 'Search' }));
    await user.selectOptions(screen.getByLabelText('Time range'), '7d');

    await vi.waitFor(() => {
      expect(lastSearch(fetchMock).get('q')).toBe('user.name:root AND event.outcome:failure');
    });
    const start = Date.parse(lastSearch(fetchMock).get('start') ?? '');
    expect(Date.now() - start).toBeGreaterThan(6 * 24 * 3_600_000);
  });

  it('takes the query from the address, as entity pages link to it', async () => {
    const fetchMock = stubApi((path) =>
      path === '/events'
        ? { status: 200, body: { items: [event(1)], next_cursor: null } }
        : undefined,
    );
    renderAt('/events?q=ip%3A203.0.113.45&range=24h');

    expect(await screen.findByLabelText('Query')).toHaveValue('ip:203.0.113.45');
    expect(screen.getByLabelText('Time range')).toHaveValue('24h');
    expect(lastSearch(fetchMock).get('q')).toBe('ip:203.0.113.45');
    expect(await screen.findByRole('link', { name: 'web-01' })).toHaveAttribute(
      'href',
      '/entities/host?value=web-01',
    );
  });

  it('shows query errors from the API', async () => {
    stubApi((path) =>
      path === '/events'
        ? {
            status: 422,
            body: { detail: "unknown field 'hostname'; did you mean host.name? (at character 1)" },
          }
        : undefined,
    );
    renderAt('/events?q=hostname%3Ax');

    expect(await screen.findByRole('alert')).toHaveTextContent('did you mean host.name?');
  });

  it('pins an event to a case as evidence', async () => {
    const user = userEvent.setup();
    const pinned: StubRequest[] = [];
    stubApi((path, _params, request) => {
      if (path === '/events')
        return { status: 200, body: { items: [event(5)], next_cursor: null } };
      if (path === '/cases') return { status: 200, body: { items: [caseSummary()], total: 1 } };
      if (path === '/cases/7/evidence') {
        pinned.push(request);
        return { status: 201, body: {} };
      }
      return undefined;
    });
    renderAt('/events');

    await user.click(await screen.findByRole('button', { name: /2026-10-12/ }));
    const form = await screen.findByRole('form', { name: 'Pin as evidence' });
    await within(form).findByRole('option', { name: '#7 SSH brute force on web-01' });
    await user.selectOptions(within(form).getByLabelText('Case'), '7');
    await user.type(within(form).getByLabelText('Note'), 'First failure');
    await user.click(within(form).getByRole('button', { name: 'Pin as evidence' }));

    expect(await within(form).findByRole('status')).toHaveTextContent('Pinned to case #7');
    expect(pinned.map((request) => request.body)).toEqual([{ event_id: 5, note: 'First failure' }]);
  });

  it('points to the cases page when no case is open', async () => {
    const user = userEvent.setup();
    stubApi((path) => {
      if (path === '/events')
        return { status: 200, body: { items: [event(5)], next_cursor: null } };
      if (path === '/cases') return { status: 200, body: { items: [], total: 0 } };
      return undefined;
    });
    renderAt('/events');

    await user.click(await screen.findByRole('button', { name: /2026-10-12/ }));

    expect(await screen.findByText(/to pin this event as evidence/)).toBeInTheDocument();
  });
});
