import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { EventRecord } from '../api/types';
import { renderAt, requestUrl, stubApi } from '../test/utils';

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

    expect(
      await screen.findByText('No events have matched a threat indicator.'),
    ).toBeInTheDocument();
  });
});
