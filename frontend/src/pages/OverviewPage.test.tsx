import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ReadinessResponse } from '../api/types';
import { dashboard } from '../test/fixtures';
import { renderAt, requestUrl, stubApi } from '../test/utils';

const HEALTH = { status: 'ok', version: '0.1.0', environment: 'development' };

function readiness(body: ReadinessResponse, status = 200) {
  return { status, body };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('OverviewPage', () => {
  it('shows an operational platform when every dependency is healthy', async () => {
    stubApi((path) => {
      if (path === '/health') return { status: 200, body: HEALTH };
      if (path === '/health/ready')
        return readiness({
          status: 'ok',
          checks: {
            database: { status: 'ok', latency_ms: 1.25, error: null },
            redis: { status: 'ok', latency_ms: 0.4, error: null },
          },
        });
      return undefined;
    });

    renderAt('/');

    const platform = await screen.findByRole('region', { name: 'Platform' });
    expect(await within(platform).findByText('Operational')).toBeInTheDocument();
    expect(within(platform).getByText('0.1.0')).toBeInTheDocument();

    const database = screen.getByRole('region', { name: 'PostgreSQL' });
    expect(within(database).getByText('Healthy')).toBeInTheDocument();
    expect(within(database).getByText('1.3 ms')).toBeInTheDocument();
  });

  it('flags a degraded platform and names the failing dependency', async () => {
    stubApi((path) => {
      if (path === '/health') return { status: 200, body: HEALTH };
      if (path === '/health/ready')
        return readiness(
          {
            status: 'degraded',
            checks: {
              database: { status: 'ok', latency_ms: 2, error: null },
              redis: { status: 'error', latency_ms: null, error: 'ConnectionError' },
            },
          },
          503,
        );
      return undefined;
    });

    renderAt('/');

    expect(await screen.findByText('Degraded')).toBeInTheDocument();
    const redis = screen.getByRole('region', { name: 'Redis' });
    expect(within(redis).getByText('Unavailable')).toBeInTheDocument();
    expect(within(redis).getByText('ConnectionError')).toBeInTheDocument();
  });

  it('reports when the API cannot be reached', async () => {
    stubApi(() => ({ status: 502, body: {} }));

    renderAt('/');

    expect(await screen.findByText('API unreachable', { selector: '.status' })).toBeInTheDocument();
  });
});

describe('OverviewPage dashboard', () => {
  function stubDashboard(body = dashboard()) {
    return stubApi((path) => (path === '/dashboard' ? { status: 200, body } : undefined));
  }

  it('shows the headline numbers and links into the queues', async () => {
    stubDashboard();
    renderAt('/');

    const glance = await screen.findByRole('region', { name: 'At a glance' });
    expect(within(glance).getByRole('link', { name: '4' })).toHaveAttribute('href', '/alerts');
    expect(within(glance).getByRole('link', { name: '1' })).toHaveAttribute('href', '/cases');
    expect(within(glance).getByText('1,234')).toBeInTheDocument();
  });

  it('charts alerts and ingestion over time', async () => {
    stubDashboard();
    renderAt('/');

    expect(
      await screen.findByRole('img', {
        name: 'Alerts over time: 6 alerts in 4 intervals, at most 4 in one',
      }),
    ).toBeInTheDocument();
    const chart = screen.getByRole('region', { name: 'Alerts over time' });
    expect(within(chart).getByText('10-14 01:00: 1 critical')).toBeInTheDocument();
    expect(within(chart).getByText('10-14 00:00: no alerts')).toBeInTheDocument();
    expect(within(chart).getByText('peak 4')).toBeInTheDocument();
    expect(
      screen.getByRole('img', {
        name: 'Events stored over time: 1,234 events in 4 intervals, at most 1,234 in one',
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/1,234 events stored by 2 jobs, 617 events\/s on average/),
    ).toBeInTheDocument();
  });

  it('ranks severities, addresses, users and rules with links', async () => {
    stubDashboard();
    renderAt('/');

    const severities = await screen.findByRole('list', { name: 'Alerts by severity' });
    expect(within(severities).getByRole('link', { name: 'Critical' })).toHaveAttribute(
      'href',
      '/alerts?severity=critical',
    );
    expect(within(severities).getByText('3 still open')).toBeInTheDocument();

    const ips = screen.getByRole('list', { name: 'Source addresses with the most alerts' });
    expect(within(ips).getByRole('link', { name: '203.0.113.45' })).toHaveAttribute(
      'href',
      '/entities/ip?value=203.0.113.45',
    );
    expect(within(ips).getAllByTitle('In the threat intel store')).toHaveLength(1);
    expect(within(ips).getByText('31 events')).toBeInTheDocument();

    const users = screen.getByRole('list', { name: 'Users with the most alerts' });
    expect(within(users).getByRole('link', { name: 'root' })).toBeInTheDocument();
    const rules = screen.getByRole('list', { name: 'Rules that raised the most alerts' });
    expect(within(rules).getByRole('link', { name: 'SSH brute force' })).toHaveAttribute(
      'href',
      '/alerts?rule=ssh-brute-force',
    );
  });

  it('shows resolution times', async () => {
    stubDashboard();
    renderAt('/');

    const resolve = await screen.findByRole('region', { name: 'Time to resolve' });
    expect(within(resolve).getByText('4.0 h')).toBeInTheDocument();
    expect(within(resolve).getByText('2.0 h')).toBeInTheDocument();
    expect(within(resolve).getAllByText('—')).toHaveLength(2);
  });

  it('asks for the chosen period', async () => {
    const user = userEvent.setup();
    const fetchMock = stubDashboard();
    renderAt('/');
    await screen.findByRole('region', { name: 'At a glance' });

    await user.selectOptions(screen.getByLabelText('Period'), '30d');

    const ranges = fetchMock.mock.calls
      .map(([input]) => requestUrl(input))
      .filter((url) => url.pathname === '/api/dashboard')
      .map((url) => url.searchParams.get('range'));
    expect(ranges).toEqual(['7d', '30d']);
  });

  it('explains empty periods and failures', async () => {
    const empty = dashboard({
      alerts_over_time: dashboard().alerts_over_time.map((bucket) => ({
        ...bucket,
        critical: 0,
        medium: 0,
        low: 0,
      })),
      ingestion: { series: [], events_ingested: 0, jobs: 0, events_per_second: null },
      top_source_ips: [],
      top_users: [],
      top_rules: [],
    });
    stubDashboard(empty);
    const { unmount } = renderAt('/');
    expect(
      await screen.findByText('No alerts in this period.', { selector: '.chart__empty' }),
    ).toBeInTheDocument();
    expect(screen.getByText('No alerts with a source address in this period.')).toBeInTheDocument();
    expect(screen.getByText('No rule fired in this period.')).toBeInTheDocument();
    expect(screen.getByText('0 events stored by 0 jobs.')).toBeInTheDocument();
    unmount();

    stubApi((path) =>
      path === '/dashboard' ? { status: 500, body: { detail: 'database down' } } : undefined,
    );
    renderAt('/');
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Could not load the dashboard: database down',
    );
  });
});
