import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AlertDetail, AlertTimeline } from '../api/types';
import {
  alertDetail,
  analyst,
  caseSummary,
  enrichment,
  eventRecord,
  MIMIKATZ_SHA256,
  virusTotalAnswer,
} from '../test/fixtures';
import { renderAt, type StubRequest, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

type Reply = { status: number; body?: unknown } | undefined;

const TIMELINE: AlertTimeline = {
  start: '2026-10-12T08:32:13Z',
  end: '2026-10-12T09:32:51Z',
  window_minutes: 30,
  entities: { 'host.name': 'web-01', 'source.ip': '203.0.113.45' },
  truncated: false,
  events: [
    { ...eventRecord(1), is_evidence: true },
    {
      ...eventRecord(2, {
        timestamp: '2026-10-12T09:05:00Z',
        user_name: 'backup',
        event_outcome: 'success',
        message: 'Accepted password for backup from 203.0.113.45',
      }),
      is_evidence: false,
    },
  ],
};

function stubAlert(
  detail: AlertDetail = alertDetail(),
  extra: (path: string, params: URLSearchParams, request: StubRequest) => Reply = () => undefined,
) {
  return stubApi((path, params, request) => {
    const special = extra(path, params, request);
    if (special) return special;
    if (path === '/alerts/11' && request.method === 'GET') return { status: 200, body: detail };
    if (path === '/alerts/11/timeline') return { status: 200, body: TIMELINE };
    if (path === '/users') return { status: 200, body: [analyst()] };
    if (path === '/cases') return { status: 200, body: { items: [caseSummary()], total: 1 } };
    return undefined;
  });
}

describe('AlertPage', () => {
  it('shows the alert, its rule, timeline and evidence', async () => {
    stubAlert(
      alertDetail({
        activity: [
          {
            id: 1,
            occurred_at: '2026-10-12T09:30:00Z',
            username: null,
            action: 'alert.status_changed',
            details: { from: 'new', to: 'investigating' },
          },
        ],
      }),
    );
    renderAt('/alerts/11');

    expect(
      await screen.findByRole('heading', { name: 'SSH brute force: 203.0.113.45' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Many failed SSH logins from one address.')).toBeInTheDocument();
    expect(screen.getByText('Users retrying an expired password')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'SSH brute force' })).toHaveAttribute(
      'href',
      '/rules/ssh-brute-force',
    );
    expect(screen.getByRole('link', { name: 'T1110.001' })).toHaveAttribute(
      'href',
      '/alerts?technique=T1110.001',
    );
    expect(screen.getByText(/changed the status from new to investigating/)).toBeInTheDocument();

    const timeline = screen.getByRole('region', { name: 'Timeline' });
    expect(await within(timeline).findByText('Evidence')).toBeInTheDocument();
    expect(
      within(timeline).getByText('Accepted password for backup from 203.0.113.45'),
    ).toBeInTheDocument();
    expect(
      within(timeline).getByText(/involving host\.name web-01, source\.ip/),
    ).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Evidence (1 of 10 events)' })).toBeInTheDocument();
  });

  it('changes the timeline window', async () => {
    const user = userEvent.setup();
    const windows: (string | null)[] = [];
    stubAlert(alertDetail(), (path, params) => {
      if (path === '/alerts/11/timeline') windows.push(params.get('window_minutes'));
      return undefined;
    });
    renderAt('/alerts/11');

    const timeline = await screen.findByRole('region', { name: 'Timeline' });
    await user.selectOptions(within(timeline).getByLabelText('Window'), '240');

    await vi.waitFor(() => {
      expect(windows).toEqual(['30', '240']);
    });
  });

  it('triages the alert', async () => {
    const user = userEvent.setup();
    const sent: unknown[] = [];
    stubAlert(alertDetail(), (path, _params, request) => {
      if (path === '/alerts/11' && request.method === 'PATCH') {
        sent.push(request.body);
        return { status: 200, body: alertDetail() };
      }
      return undefined;
    });
    renderAt('/alerts/11');

    const triage = await screen.findByRole('region', { name: 'Triage' });
    await user.selectOptions(within(triage).getByLabelText('Status'), 'true_positive');
    await within(triage).findByRole('option', { name: 'Analyst One (analyst.one)' });
    await user.selectOptions(within(triage).getByLabelText('Assignee'), '3');

    expect(sent).toEqual([{ status: 'true_positive' }, { assignee_id: 3 }]);
  });

  it('explains why an alert cannot be reopened', async () => {
    const user = userEvent.setup();
    stubAlert(alertDetail({ status: 'closed' }), (path, _params, request) =>
      path === '/alerts/11' && request.method === 'PATCH'
        ? { status: 409, body: { detail: 'alert 30 is already open for the same rule and entity' } }
        : undefined,
    );
    renderAt('/alerts/11');

    const triage = await screen.findByRole('region', { name: 'Triage' });
    await user.selectOptions(within(triage).getByLabelText('Status'), 'new');

    expect(await within(triage).findByRole('alert')).toHaveTextContent('alert 30 is already open');
  });

  it('links to its case, or offers to add it to one', async () => {
    stubAlert(alertDetail({ case_id: 7 }));
    const { unmount } = renderAt('/alerts/11');
    expect(await screen.findByRole('link', { name: 'case #7' })).toHaveAttribute(
      'href',
      '/cases/7',
    );
    unmount();

    const user = userEvent.setup();
    const sent: unknown[] = [];
    stubAlert(alertDetail(), (path, _params, request) => {
      if (path === '/cases/7/alerts') {
        sent.push(request.body);
        return { status: 200, body: { added: [11] } };
      }
      return undefined;
    });
    renderAt('/alerts/11');
    const form = await screen.findByRole('form', { name: 'Add to case' });
    expect(within(form).getByLabelText('Title')).toHaveValue('SSH brute force: 203.0.113.45');
    await within(form).findByRole('option', { name: '#7 SSH brute force on web-01' });
    await user.selectOptions(within(form).getByLabelText('Case'), '7');
    await user.click(within(form).getByRole('button', { name: 'Add to case' }));

    expect(sent).toEqual([{ alert_ids: [11] }]);
    expect(await within(form).findByRole('status')).toHaveTextContent('Saved to case #7');
  });

  it('handles missing alerts and bad addresses', async () => {
    stubApi(() => ({ status: 404, body: { detail: 'alert not found' } }));
    const { unmount } = renderAt('/alerts/99');
    expect(await screen.findByText(/Could not load this alert/)).toBeInTheDocument();
    unmount();

    renderAt('/alerts/not-a-number');
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});

describe('AlertPage threat intelligence', () => {
  async function openAlert(detail: AlertDetail, enrich?: (refresh: string | null) => Reply) {
    const user = userEvent.setup();
    stubAlert(detail, (path, params) =>
      path === '/alerts/11/enrich' && enrich ? enrich(params.get('refresh')) : undefined,
    );
    renderAt('/alerts/11');
    const panel = await screen.findByRole('region', { name: 'Threat intelligence' });
    return { user, panel };
  }

  it('shows each indicator with local intel and provider answers', async () => {
    const { panel } = await openAlert(alertDetail({ enrichment: enrichment() }));

    // Overall, both indicators, and VirusTotal's answer.
    expect(within(panel).getAllByText('Malicious')).toHaveLength(4);
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
    const { panel } = await openAlert(alertDetail({ enrichment: postponed }));

    expect(within(panel).getByText(/rate limit and will be retried/)).toBeInTheDocument();
    expect(within(panel).getByText('Postponed')).toBeInTheDocument();
  });

  it('checks an alert that was never enriched, then refreshes it', async () => {
    const refreshes: (string | null)[] = [];
    const { user, panel } = await openAlert(alertDetail(), (refresh) => {
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
    const { user, panel } = await openAlert(alertDetail(), () => ({
      status: 404,
      body: { detail: 'alert not found' },
    }));

    await user.click(within(panel).getByRole('button', { name: 'Check indicators' }));

    expect(await within(panel).findByRole('alert')).toHaveTextContent('alert not found');
  });

  it('notes alerts without any indicators', async () => {
    const { panel } = await openAlert(
      alertDetail({ enrichment: enrichment({ verdict: 'unknown', indicators: [] }) }),
    );

    expect(within(panel).getByText(/No IP addresses, domains or file hashes/)).toBeInTheDocument();
    expect(within(panel).getByText('Unknown')).toBeInTheDocument();
  });
});
