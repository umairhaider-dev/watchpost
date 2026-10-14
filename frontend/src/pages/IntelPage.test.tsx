import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type {
  FeedImportResult,
  IntelSummary,
  IocDetail,
  LookupResult,
  ProvidersInfo,
} from '../api/types';
import { ioc, MIMIKATZ_SHA256, virusTotalAnswer } from '../test/fixtures';
import { renderAt, requestUrl, type StubRequest, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

const SUMMARY: IntelSummary = {
  total: 5,
  active: 5,
  by_type: { ip: 3, domain: 1, sha256: 1 },
  matched_events: 31,
  indicators_matched: 3,
};

const OFFLINE: ProvidersInfo = {
  online: false,
  cache_hours: 24,
  providers: [
    {
      name: 'abuseipdb',
      label: 'AbuseIPDB',
      configured: false,
      cooling_down: false,
      remaining: {},
    },
    {
      name: 'virustotal',
      label: 'VirusTotal',
      configured: false,
      cooling_down: false,
      remaining: {},
    },
  ],
};

const HASH = ioc({
  id: 4,
  ioc_type: 'sha256',
  value: MIMIKATZ_SHA256,
  description: 'Credential dumping tool (Mimikatz build)',
  confidence: 95,
  tags: ['credential-access', 'malware'],
  match_count: 0,
  last_matched_at: null,
});

type Reply = { status: number; body?: unknown } | undefined;
type Extra = (path: string, params: URLSearchParams, request: StubRequest) => Reply;

/** The intel API with two indicators; ``extra`` answers anything else first. */
function stubIntel(extra: Extra = () => undefined) {
  return stubApi((path, params, request) => {
    const special = extra(path, params, request);
    if (special) return special;
    if (path === '/intel/summary') return { status: 200, body: SUMMARY };
    if (path === '/intel/providers') return { status: 200, body: OFFLINE };
    if (path === '/intel/iocs' && request.method === 'GET') {
      return { status: 200, body: { items: [ioc(), HASH], total: 2 } };
    }
    return undefined;
  });
}

function requestsTo(fetchMock: ReturnType<typeof stubApi>, path: string) {
  return fetchMock.mock.calls
    .map(([input, init]) => ({ url: requestUrl(input), init }))
    .filter(({ url }) => url.pathname === `/api${path}`);
}

describe('IntelPage', () => {
  it('shows the store, its indicators and that lookups are offline', async () => {
    stubIntel();
    renderAt('/intel');

    expect(await screen.findByRole('heading', { name: 'Threat intel' })).toBeInTheDocument();
    const store = screen.getByRole('region', { name: 'Indicator store' });
    expect(await within(store).findByText('31')).toBeInTheDocument();
    expect(within(store).getByText('3 IP · 1 Domain · 1 SHA-256')).toBeInTheDocument();

    const table = screen.getByRole('region', { name: 'Indicators' });
    expect(await within(table).findByText('203.0.113.45')).toBeInTheDocument();
    expect(within(table).getByText(MIMIKATZ_SHA256)).toBeInTheDocument();
    expect(within(table).getByText('12')).toHaveClass('text-warn');

    const providers = screen.getByRole('region', { name: 'Online lookups' });
    expect(await within(providers).findByText(/Working offline/)).toBeInTheDocument();
    expect(within(providers).getAllByText('Not configured')).toHaveLength(2);
  });

  it('sends search, type and matched filters', async () => {
    const user = userEvent.setup();
    const fetchMock = stubIntel();
    renderAt('/intel');
    await screen.findByText('203.0.113.45');

    const table = screen.getByRole('region', { name: 'Indicators' });
    await user.type(within(table).getByLabelText('Search indicators'), 'mimikatz');
    await user.selectOptions(within(table).getByLabelText('Type'), 'sha256');
    await user.click(within(table).getByRole('button', { name: 'Seen in events' }));

    const last = requestsTo(fetchMock, '/intel/iocs').at(-1);
    expect(last?.url.searchParams.get('q')).toBe('mimikatz');
    expect(last?.url.searchParams.get('ioc_type')).toBe('sha256');
    expect(last?.url.searchParams.get('matched')).toBe('true');
  });

  it('expands an indicator to list the events it matched', async () => {
    const user = userEvent.setup();
    const detail: IocDetail = {
      ...ioc(),
      matches: [
        {
          event_id: 7,
          field: 'source.ip',
          matched_at: '2026-10-14T08:00:05Z',
          timestamp: '2026-10-12T09:02:13Z',
          log_source: 'linux_auth',
          host_name: 'web-01',
          source_ip: '203.0.113.45',
          user_name: 'root',
          event_action: 'ssh_login',
          message: 'Failed password for root from 203.0.113.45',
        },
      ],
    };
    stubIntel((path) => (path === '/intel/iocs/1' ? { status: 200, body: detail } : undefined));
    renderAt('/intel');

    await user.click(await screen.findByRole('button', { name: '203.0.113.45' }));

    expect(
      await screen.findByText('Failed password for root from 203.0.113.45'),
    ).toBeInTheDocument();
    expect(screen.getByText('source.ip')).toBeInTheDocument();
    expect(screen.getByText('never')).toBeInTheDocument();
  });

  it('deactivates and deletes indicators', async () => {
    const user = userEvent.setup();
    const sent: StubRequest[] = [];
    stubIntel((path, _params, request) => {
      if (path === '/intel/iocs/1' && request.method === 'PATCH') {
        sent.push(request);
        return { status: 200, body: ioc({ is_active: false }) };
      }
      if (path === '/intel/iocs/4' && request.method === 'DELETE') {
        sent.push(request);
        return { status: 204 };
      }
      return undefined;
    });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    renderAt('/intel');

    await user.click(await screen.findByRole('switch', { name: 'Deactivate 203.0.113.45' }));
    await user.click(screen.getByRole('button', { name: `Delete ${MIMIKATZ_SHA256}` }));

    expect(confirm).toHaveBeenCalledWith(expect.stringContaining(MIMIKATZ_SHA256));
    await vi.waitFor(() => {
      expect(sent.map((request) => request.method)).toEqual(['PATCH', 'DELETE']);
    });
    expect(sent[0]?.body).toEqual({ is_active: false });
  });

  it('keeps an indicator when the delete is not confirmed', async () => {
    const user = userEvent.setup();
    const fetchMock = stubIntel();
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    renderAt('/intel');

    await user.click(await screen.findByRole('button', { name: 'Delete 203.0.113.45' }));

    expect(
      requestsTo(fetchMock, '/intel/iocs/1').filter(({ init }) => init?.method === 'DELETE'),
    ).toHaveLength(0);
  });

  it('imports a feed with its options and reports skipped lines', async () => {
    const user = userEvent.setup();
    const result: FeedImportResult = {
      filename: 'partner.csv',
      source: 'partner',
      indicators: 5,
      created: 4,
      updated: 1,
      duplicates: 0,
      problem_count: 1,
      problems: [{ line: 7, reason: 'not an IP address, domain or file hash', excerpt: 'x' }],
      truncated: false,
      sweep_queued: true,
    };
    const fetchMock = stubIntel((path) =>
      path === '/intel/import' ? { status: 200, body: result } : undefined,
    );
    renderAt('/intel');
    const card = await screen.findByRole('region', { name: 'Import a feed' });

    await user.upload(
      within(card).getByLabelText('Feed file'),
      new File(['value\n203.0.113.45\n'], 'partner.csv', { type: 'text/csv' }),
    );
    await user.type(within(card).getByLabelText('Source name'), 'partner');
    await user.type(within(card).getByLabelText('Default confidence'), '70');
    await user.click(within(card).getByRole('button', { name: 'Import feed' }));

    expect(
      await within(card).findByText(/Imported 5 indicators from partner\.csv: 4 new, 1 updated/),
    ).toBeInTheDocument();
    expect(within(card).getByText(/1 line\s+skipped/)).toBeInTheDocument();
    expect(within(card).getByText('line 7')).toBeInTheDocument();
    expect(within(card).getByText(/being checked against them/)).toBeInTheDocument();
    const [upload] = requestsTo(fetchMock, '/intel/import');
    const form = upload?.init?.body;
    expect(form).toBeInstanceOf(FormData);
    expect((form as FormData).get('source')).toBe('partner');
    expect((form as FormData).get('confidence')).toBe('70');
    expect((form as FormData).has('tags')).toBe(false);
  });

  it('shows why a feed was rejected', async () => {
    const user = userEvent.setup();
    stubIntel((path) =>
      path === '/intel/import'
        ? { status: 422, body: { detail: 'no usable indicators; first problem on line 1' } }
        : undefined,
    );
    renderAt('/intel');
    const card = await screen.findByRole('region', { name: 'Import a feed' });

    await user.upload(
      within(card).getByLabelText('Feed file'),
      new File(['nothing'], 'empty.txt', { type: 'text/plain' }),
    );
    await user.click(within(card).getByRole('button', { name: 'Import feed' }));

    expect(await within(card).findByRole('alert')).toHaveTextContent('no usable indicators');
  });

  it('adds an indicator and shows validation errors', async () => {
    const user = userEvent.setup();
    const sent: unknown[] = [];
    stubIntel((path, _params, request) => {
      if (path !== '/intel/iocs' || request.method !== 'POST') return undefined;
      sent.push(request.body);
      const body = request.body as { value: string };
      if (body.value === 'nope') {
        return { status: 422, body: { detail: "not an IP address, domain or file hash: 'nope'" } };
      }
      return { status: 201, body: ioc({ id: 9, ioc_type: 'domain', value: 'loader.example.org' }) };
    });
    renderAt('/intel');
    const card = await screen.findByRole('region', { name: 'Add an indicator' });

    // "[[" types a literal "[" (a single one starts a key name).
    await user.type(within(card).getByLabelText('Value'), 'loader[[.]example[[.]org');
    await user.type(within(card).getByLabelText('Tags'), 'c2, loader');
    await user.type(within(card).getByLabelText('Confidence'), '90');
    await user.click(within(card).getByRole('button', { name: 'Add indicator' }));

    expect(await within(card).findByRole('status')).toHaveTextContent('Saved loader.example.org');
    expect(sent[0]).toEqual({
      value: 'loader[.]example[.]org',
      tags: ['c2', 'loader'],
      confidence: 90,
    });

    await user.type(within(card).getByLabelText('Value'), 'nope');
    await user.click(within(card).getByRole('button', { name: 'Add indicator' }));
    expect(await within(card).findByRole('alert')).toHaveTextContent('not an IP address');
  });

  it('looks up an indicator and shows each source', async () => {
    const user = userEvent.setup();
    const result: LookupResult = {
      ioc_type: 'sha256',
      value: MIMIKATZ_SHA256,
      verdict: 'malicious',
      shared: true,
      online: true,
      intel: [HASH],
      providers: [virusTotalAnswer()],
    };
    const fetchMock = stubIntel((path) =>
      path === '/intel/lookup' ? { status: 200, body: result } : undefined,
    );
    renderAt('/intel');
    const card = await screen.findByRole('region', { name: 'Look up an indicator' });

    await user.type(
      within(card).getByLabelText(/IP address, domain or file hash/),
      MIMIKATZ_SHA256,
    );
    await user.click(within(card).getByRole('button', { name: 'Look up' }));

    const answer = await within(card).findByLabelText('Lookup result');
    expect(within(answer).getAllByText('Malicious')).toHaveLength(2);
    expect(
      within(answer).getByText('Credential dumping tool (Mimikatz build)'),
    ).toBeInTheDocument();
    expect(
      within(answer).getByText('52 of 70 engines flag it · m.exe · Win32 EXE'),
    ).toBeInTheDocument();
    expect(within(answer).getByRole('link', { name: 'Open in VirusTotal' })).toHaveAttribute(
      'rel',
      'noreferrer noopener',
    );

    await user.click(within(card).getByRole('button', { name: 'Ask the providers again' }));
    await vi.waitFor(() => {
      expect(requestsTo(fetchMock, '/intel/lookup').at(-1)?.url.searchParams.get('refresh')).toBe(
        'true',
      );
    });
  });

  it('queues a re-check of stored events', async () => {
    const user = userEvent.setup();
    stubIntel((path) =>
      path === '/intel/sweep' ? { status: 202, body: { queued: true } } : undefined,
    );
    renderAt('/intel');

    await user.click(await screen.findByRole('button', { name: 'Re-check stored events' }));

    expect(await screen.findByText(/every stored event will be checked/)).toBeInTheDocument();
  });

  it('shows configured providers and their remaining budget', async () => {
    stubIntel((path) =>
      path === '/intel/providers'
        ? {
            status: 200,
            body: {
              online: true,
              cache_hours: 24,
              providers: [
                {
                  name: 'virustotal',
                  label: 'VirusTotal',
                  configured: true,
                  cooling_down: true,
                  remaining: { '4/min': 3, '500/day': 499 },
                },
              ],
            } satisfies ProvidersInfo,
          }
        : undefined,
    );
    renderAt('/intel');
    const card = await screen.findByRole('region', { name: 'Online lookups' });

    expect(
      await within(card).findByText('3 left of 4/min · 499 left of 500/day'),
    ).toBeInTheDocument();
    expect(within(card).getByText('Configured')).toBeInTheDocument();
    expect(within(card).getByText(/Paused by the provider/)).toBeInTheDocument();
    expect(within(card).getByText(/cached for 24 hours/)).toBeInTheDocument();
  });
});
