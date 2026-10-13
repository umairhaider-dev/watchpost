import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AlertDetail } from '../api/types';
import { alertSummary } from '../test/fixtures';
import { renderAt, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

const DETAIL: AlertDetail = {
  ...alertSummary(),
  enrichment: {},
  rule: {
    id: 'ssh-brute-force',
    title: 'SSH brute force',
    description: 'Many failed SSH logins from one address.',
    false_positives: [],
  },
  evidence: [
    {
      id: 1,
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
      process_pid: 3104,
      process_executable: null,
      process_command_line: null,
      process_parent_name: null,
      process_parent_pid: null,
      url_original: null,
      http_method: null,
      http_status_code: null,
      user_agent: null,
      message: 'Failed password for root from 203.0.113.45',
      ioc_matched: false,
      raw_event: { line: 'raw' },
    },
  ],
};

describe('AlertsPage', () => {
  it('lists alerts and expands one to show its evidence', async () => {
    const user = userEvent.setup();
    stubApi((path) => {
      if (path === '/alerts') return { status: 200, body: { items: [alertSummary()], total: 1 } };
      if (path === '/alerts/11') return { status: 200, body: DETAIL };
      return undefined;
    });
    renderAt('/alerts');

    const toggle = await screen.findByRole('button', { name: /SSH brute force: 203\.0\.113\.45/ });
    expect(screen.getByText('web-01 · root · 203.0.113.45')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();

    await user.click(toggle);

    expect(await screen.findByText('Evidence (1 of 10 events)')).toBeInTheDocument();
    expect(screen.getByText('Failed password for root from 203.0.113.45')).toBeInTheDocument();
    expect(screen.getByText('Many failed SSH logins from one address.')).toBeInTheDocument();
  });

  it('sends severity, status and rule filters to the API', async () => {
    const user = userEvent.setup();
    const fetchMock = stubApi((path) =>
      path === '/alerts' ? { status: 200, body: { items: [], total: 0 } } : undefined,
    );
    renderAt('/alerts?rule=ssh-brute-force');
    expect(await screen.findByText('No alerts match these filters.')).toBeInTheDocument();
    expect(screen.getByText('Alerts from ssh-brute-force')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'critical' }));
    await user.click(screen.getByRole('button', { name: 'high' }));
    await user.selectOptions(screen.getByLabelText('Status'), 'new');

    const urls = fetchMock.mock.calls.map(([input]) =>
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
    );
    const last = new URL(urls.at(-1) ?? '', 'http://localhost');
    expect(last.searchParams.getAll('severity')).toEqual(['critical', 'high']);
    expect(last.searchParams.get('status')).toBe('new');
    expect(last.searchParams.get('rule_id')).toBe('ssh-brute-force');
    expect(screen.getByRole('button', { name: 'critical' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );

    await user.click(screen.getByRole('button', { name: 'critical' }));
    expect(screen.getByRole('button', { name: 'critical' })).toHaveAttribute(
      'aria-pressed',
      'false',
    );
  });

  it('reports errors loading alert details', async () => {
    const user = userEvent.setup();
    stubApi((path) =>
      path === '/alerts'
        ? { status: 200, body: { items: [alertSummary()], total: 1 } }
        : { status: 500, body: {} },
    );
    renderAt('/alerts');

    await user.click(await screen.findByRole('button', { name: /SSH brute force/ }));

    expect(await screen.findByText('Could not load this alert.')).toBeInTheDocument();
  });
});
