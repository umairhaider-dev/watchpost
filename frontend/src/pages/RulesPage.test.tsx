import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { RuleSummary } from '../api/types';
import { detectionRun, ruleDetail, ruleSummary } from '../test/fixtures';
import { renderAt, stubApi, type StubRequest } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

function stubRules(rules: RuleSummary[], requests: (StubRequest & { path: string })[] = []) {
  return stubApi((path, _params, request) => {
    if (request.method !== 'GET') requests.push({ ...request, path });
    if (path === '/rules') return { status: 200, body: rules };
    if (path === '/detection/runs' && request.method === 'GET') {
      return { status: 200, body: [detectionRun()] };
    }
    if (path === '/detection/runs')
      return { status: 202, body: detectionRun({ id: 5, status: 'queued' }) };
    if (path.startsWith('/rules/') && request.method === 'PATCH') {
      const id = path.split('/')[2] ?? '';
      const enabled = (request.body as { enabled: boolean }).enabled;
      return { status: 200, body: ruleDetail({ id, enabled }) };
    }
    return undefined;
  });
}

describe('RulesPage', () => {
  it('lists rules by severity with their ATT&CK techniques', async () => {
    stubRules([
      ruleSummary(),
      ruleSummary({
        id: 'sysmon-lsass-memory-access',
        title: 'LSASS process memory accessed',
        severity: 'critical',
        techniques: [{ id: 'T1003.001', name: 'LSASS Memory' }],
      }),
      ruleSummary({
        id: 'linux-user-created',
        title: 'Local user account created',
        severity: 'low',
        enabled: false,
      }),
    ]);

    renderAt('/rules');

    const links = await screen.findAllByRole('link', { name: /SSH brute force|LSASS|Local user/ });
    expect(links.map((link) => link.textContent)).toEqual([
      'LSASS process memory accessed',
      'SSH brute force',
      'Local user account created',
    ]);
    expect(screen.getByText('2 of 3 enabled')).toBeInTheDocument();
    expect(screen.getByText('T1003.001')).toHaveAttribute('title', 'LSASS Memory');
  });

  it('filters by title or technique', async () => {
    const user = userEvent.setup();
    stubRules([
      ruleSummary(),
      ruleSummary({
        id: 'web-sql-injection',
        title: 'SQL injection attempt',
        techniques: [{ id: 'T1190', name: null }],
      }),
    ]);
    renderAt('/rules');
    await screen.findByText('SQL injection attempt');

    await user.type(screen.getByLabelText('Filter rules'), 't1190');

    expect(screen.getByText('SQL injection attempt')).toBeInTheDocument();
    expect(screen.queryByText('SSH brute force')).not.toBeInTheDocument();

    await user.clear(screen.getByLabelText('Filter rules'));
    await user.type(screen.getByLabelText('Filter rules'), 'nothing matches');
    expect(screen.getByText(/No rule matches/)).toBeInTheDocument();
  });

  it('toggles a rule with its switch', async () => {
    const user = userEvent.setup();
    const requests: (StubRequest & { path: string })[] = [];
    stubRules([ruleSummary()], requests);
    renderAt('/rules');

    const toggle = await screen.findByRole('switch', { name: 'Disable SSH brute force' });
    expect(toggle).toHaveAttribute('aria-checked', 'true');
    await user.click(toggle);

    expect(requests).toContainEqual({
      method: 'PATCH',
      path: '/rules/ssh-brute-force',
      body: { enabled: false },
    });
  });

  it('starts a detection run over the chosen range', async () => {
    const user = userEvent.setup();
    const requests: (StubRequest & { path: string })[] = [];
    stubRules([ruleSummary()], requests);
    renderAt('/rules');

    const card = await screen.findByRole('region', { name: 'Detection runs' });
    expect(await within(card).findByText(/2 new,/)).toBeInTheDocument();
    await user.selectOptions(within(card).getByLabelText('Scan'), 'all');
    await user.click(within(card).getByRole('button', { name: 'Run detection' }));

    expect(requests).toContainEqual({ method: 'POST', path: '/detection/runs', body: {} });
  });

  it('shows why a detection run could not start', async () => {
    const user = userEvent.setup();
    stubApi((path, _params, request) => {
      if (path === '/rules') return { status: 200, body: [] };
      if (path === '/detection/runs' && request.method === 'GET') return { status: 200, body: [] };
      if (path === '/detection/runs')
        return { status: 503, body: { detail: 'job queue unavailable; try again shortly' } };
      return undefined;
    });
    renderAt('/rules');

    await user.click(await screen.findByRole('button', { name: 'Run detection' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('job queue unavailable');
  });
});
