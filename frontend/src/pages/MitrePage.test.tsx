import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AttackMatrix } from '../api/types';
import { renderAt, requestUrl, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

const MATRIX: AttackMatrix = {
  techniques_covered: 2,
  techniques_detected: 1,
  tactics: [
    { id: 'TA0043', name: 'Reconnaissance', techniques: [] },
    {
      id: 'TA0006',
      name: 'Credential Access',
      techniques: [
        {
          id: 'T1110.001',
          name: 'Brute Force: Password Guessing',
          rules: ['ssh-brute-force'],
          enabled_rules: 1,
          alerts: 3,
          open_alerts: 1,
          last_seen: '2026-10-12T09:02:51Z',
        },
        {
          id: 'T1110.003',
          name: 'Brute Force: Password Spraying',
          rules: ['ssh-password-spraying'],
          enabled_rules: 1,
          alerts: 0,
          open_alerts: 0,
          last_seen: null,
        },
        {
          id: 'T1003.008',
          name: null,
          rules: ['linux-shadow-read'],
          enabled_rules: 0,
          alerts: 0,
          open_alerts: 0,
          last_seen: null,
        },
      ],
    },
  ],
};

describe('MitrePage', () => {
  it('lays techniques out by tactic and links detections to their alerts', async () => {
    stubApi((path) => (path === '/mitre/matrix' ? { status: 200, body: MATRIX } : undefined));
    renderAt('/mitre');

    const column = await screen.findByRole('listitem', { name: 'Credential Access' });
    const detected = within(column).getByRole('link', { name: /^T1110\.001:/ });
    expect(detected).toHaveAttribute('href', '/alerts?technique=T1110.001');
    expect(detected).toHaveAccessibleName(
      'T1110.001: 1 of 1 rules enabled · 3 alerts (1 open) · last 2026-10-12 09:02:51 UTC',
    );
    expect(
      within(column).getByText('Brute Force: Password Spraying').closest('li'),
    ).toHaveAttribute('data-state', 'covered');
    expect(within(column).getByText('Unknown technique').closest('li')).toHaveAttribute(
      'data-state',
      'uncovered',
    );
    expect(
      within(screen.getByRole('listitem', { name: 'Reconnaissance' })).getByText('No rules yet'),
    ).toBeInTheDocument();
    expect(screen.getByText('1 of 2')).toBeInTheDocument();
  });

  it('asks for the chosen period', async () => {
    const user = userEvent.setup();
    const fetchMock = stubApi((path) =>
      path === '/mitre/matrix' ? { status: 200, body: MATRIX } : undefined,
    );
    renderAt('/mitre');
    await screen.findByRole('listitem', { name: 'Credential Access' });

    await user.selectOptions(screen.getByLabelText('Alerts from'), 'all');

    const last = fetchMock.mock.calls.map(([input]) => requestUrl(input)).at(-1);
    expect(last?.searchParams.get('since')).toBeNull();
    const first = requestUrl(fetchMock.mock.calls[0]?.[0]);
    expect(Date.now() - Date.parse(first.searchParams.get('since') ?? '')).toBeGreaterThan(
      29 * 24 * 3_600_000,
    );
  });

  it('reports errors', async () => {
    stubApi(() => ({ status: 500, body: {} }));
    renderAt('/mitre');

    expect(await screen.findByText('Could not load the matrix.')).toBeInTheDocument();
  });
});
