import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { EntityProfile } from '../api/types';
import { alertSummary, caseSummary, ioc } from '../test/fixtures';
import { renderAt, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

const PROFILE: EntityProfile = {
  kind: 'ip',
  value: '203.0.113.45',
  query: 'ip:203.0.113.45',
  event_count: 31,
  first_seen: '2026-10-12T09:00:00Z',
  last_seen: '2026-10-13T15:00:00Z',
  log_sources: [{ value: 'linux_auth', count: 31 }],
  activity: [
    { day: '2026-10-12T00:00:00Z', count: 30 },
    { day: '2026-10-13T00:00:00Z', count: 1 },
  ],
  related: {
    users: [
      { value: 'root', count: 20 },
      { value: 'backup', count: 1 },
    ],
    hosts: [{ value: 'web-01', count: 31 }],
  },
  alert_count: 2,
  open_alert_count: 1,
  alerts: [alertSummary()],
  cases: [caseSummary()],
  intel: [ioc()],
};

describe('EntityPage', () => {
  it('profiles an IP address', async () => {
    const requested: string[] = [];
    stubApi((path, params) => {
      if (path !== '/entities/ip') return undefined;
      requested.push(params.get('value') ?? '');
      return { status: 200, body: PROFILE };
    });
    renderAt('/entities/ip?value=203.0.113.45');

    expect(
      await screen.findByRole('heading', { name: 'IP address 203.0.113.45' }),
    ).toBeInTheDocument();
    expect(requested).toEqual(['203.0.113.45']);
    const activity = await screen.findByRole('region', { name: 'Activity' });
    expect(within(activity).getByText('31')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'Events per day' }).children).toHaveLength(2);
    expect(screen.getByRole('link', { name: 'Search its events' })).toHaveAttribute(
      'href',
      '/events?q=ip%3A203.0.113.45',
    );
    const related = screen.getByRole('region', { name: 'Seen with' });
    expect(within(related).getByRole('link', { name: 'root' })).toHaveAttribute(
      'href',
      '/entities/user?value=root',
    );
    expect(screen.getByText(/SSH brute-force source reported/)).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Alerts (2, 1 open)' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '#7 SSH brute force on web-01' })).toHaveAttribute(
      'href',
      '/cases/7',
    );
  });

  it('handles entities without activity, errors and bad addresses', async () => {
    stubApi((path) =>
      path === '/entities/user'
        ? {
            status: 200,
            body: {
              ...PROFILE,
              kind: 'user',
              value: 'nobody',
              event_count: 0,
              activity: [],
              related: {},
              alerts: [],
              cases: [],
              intel: [],
            },
          }
        : { status: 422, body: { detail: "'nope' is not an IP address" } },
    );
    const { unmount } = renderAt('/entities/user?value=nobody');
    expect(await screen.findByText(/No stored events involve this user/)).toBeInTheDocument();
    expect(screen.getByText('No alerts involve this entity.')).toBeInTheDocument();
    unmount();

    const invalid = renderAt('/entities/ip?value=nope');
    expect(await screen.findByRole('alert')).toHaveTextContent('is not an IP address');
    invalid.unmount();

    renderAt('/entities/process?value=x');
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});
