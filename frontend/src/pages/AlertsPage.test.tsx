import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AlertDetail } from '../api/types';
import { alertSummary, enrichment, MIMIKATZ_SHA256, virusTotalAnswer } from '../test/fixtures';
import { renderAt, stubApi } from '../test/utils';

type Reply = { status: number; body?: unknown } | undefined;

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

describe('AlertsPage threat intelligence', () => {
  /** Open the alert's details; ``enrich`` answers POST /alerts/11/enrich (given ?refresh). */
  async function openAlert(detail: AlertDetail, enrich?: (refresh: string | null) => Reply) {
    const user = userEvent.setup();
    stubApi((path, params) => {
      if (path === '/alerts') return { status: 200, body: { items: [alertSummary()], total: 1 } };
      if (path === '/alerts/11') return { status: 200, body: detail };
      if (path === '/alerts/11/enrich' && enrich) return enrich(params.get('refresh'));
      return undefined;
    });
    renderAt('/alerts');
    await user.click(await screen.findByRole('button', { name: /SSH brute force/ }));
    const panel = await screen.findByRole('region', { name: 'Threat intelligence' });
    return { user, panel };
  }

  it('shows each indicator with local intel and provider answers', async () => {
    const { panel } = await openAlert({ ...DETAIL, enrichment: enrichment() });

    // Overall, both indicators, and VirusTotal's answer.
    expect(within(panel).getAllByText('Malicious')).toHaveLength(4);
    expect(within(panel).getByText('203.0.113.45')).toBeInTheDocument();
    expect(within(panel).getByText('seen in source.ip')).toBeInTheDocument();
    expect(
      within(panel).getByText('SSH brute-force source reported by several organisations'),
    ).toBeInTheDocument();
    expect(within(panel).getByText(/never sent to online providers/)).toBeInTheDocument();
    expect(within(panel).getByText(MIMIKATZ_SHA256)).toBeInTheDocument();
    expect(within(panel).getByText('Not in the local indicator store.')).toBeInTheDocument();
    expect(within(panel).getByText(/52 of 70 engines flag it/)).toBeInTheDocument();
    expect(within(panel).getByRole('link', { name: 'Open in VirusTotal' })).toHaveAttribute(
      'href',
      `https://www.virustotal.com/gui/file/${MIMIKATZ_SHA256}`,
    );
  });

  it('says when lookups are waiting on a rate limit', async () => {
    const postponed = enrichment({ pending: true });
    const [, hash] = postponed.indicators;
    if (hash) {
      hash.providers = [
        virusTotalAnswer({
          status: 'rate_limited',
          verdict: 'unknown',
          data: {},
          fetched_at: null,
        }),
      ];
    }
    const { panel } = await openAlert({ ...DETAIL, enrichment: postponed });

    expect(within(panel).getByText(/rate limit and will be retried/)).toBeInTheDocument();
    expect(within(panel).getByText('Postponed')).toBeInTheDocument();
    expect(
      within(panel).getByText(/retried automatically/, { selector: 'span' }),
    ).toBeInTheDocument();
  });

  it('checks an alert that was never enriched, then refreshes it', async () => {
    const refreshes: (string | null)[] = [];
    const { user, panel } = await openAlert({ ...DETAIL, enrichment: {} }, (refresh) => {
      refreshes.push(refresh);
      return {
        status: 200,
        body: enrichment({ online: false, indicators: enrichment().indicators.slice(0, 1) }),
      };
    });

    expect(within(panel).getByText('Not checked yet.')).toBeInTheDocument();
    await user.click(within(panel).getByRole('button', { name: 'Check indicators' }));

    expect(await within(panel).findByText(/local indicators only/)).toBeInTheDocument();
    await user.click(within(panel).getByRole('button', { name: 'Refresh' }));
    await vi.waitFor(() => {
      expect(refreshes).toEqual([null, 'true']);
    });
  });

  it('reports a failed check', async () => {
    const { user, panel } = await openAlert({ ...DETAIL, enrichment: {} }, () => ({
      status: 404,
      body: { detail: 'alert not found' },
    }));

    await user.click(within(panel).getByRole('button', { name: 'Check indicators' }));

    expect(await within(panel).findByRole('alert')).toHaveTextContent('alert not found');
  });

  it('notes alerts without any indicators', async () => {
    const { panel } = await openAlert({
      ...DETAIL,
      enrichment: enrichment({ verdict: 'unknown', indicators: [] }),
    });

    expect(within(panel).getByText(/No IP addresses, domains or file hashes/)).toBeInTheDocument();
    expect(within(panel).getByText('Unknown')).toBeInTheDocument();
  });
});
