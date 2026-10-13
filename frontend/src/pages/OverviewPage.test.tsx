import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ReadinessResponse } from '../api/types';
import { renderAt, stubApi } from '../test/utils';

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
