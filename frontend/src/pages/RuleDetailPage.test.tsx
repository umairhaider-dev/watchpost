import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { RuleDetail, RuleTestResult } from '../api/types';
import { RULE_YAML, ruleDetail } from '../test/fixtures';
import { renderAt, stubApi, type StubRequest } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

const TEST_RESULT: RuleTestResult = {
  parser: 'linux_auth',
  events_parsed: 12,
  truncated: false,
  malformed_count: 1,
  malformed: [{ line: 13, reason: 'not a syslog line', excerpt: 'garbage' }],
  hits: [
    {
      title: 'SSH brute force: 203.0.113.45',
      group: { 'source.ip': '203.0.113.45' },
      event_count: 10,
      first_seen: '2026-10-12T09:00:00Z',
      last_seen: '2026-10-12T09:00:45Z',
      lines: [1, 2, 3],
    },
  ],
  matched_events: [
    {
      line: 1,
      timestamp: '2026-10-12T09:00:00Z',
      event_action: 'ssh_login',
      event_outcome: 'failure',
      host_name: 'web-01',
      user_name: 'root',
      source_ip: '203.0.113.45',
      message: 'Failed password for root',
    },
  ],
};

interface Captured extends StubRequest {
  path: string;
}

function stubRule(
  rule: RuleDetail,
  captured: Captured[] = [],
  overrides: Record<string, { status: number; body?: unknown }> = {},
) {
  let current = rule;
  stubApi((path, _params, request) => {
    if (request.method !== 'GET') captured.push({ ...request, path });
    const override = overrides[`${request.method} ${path}`];
    if (override) return override;
    if (path === '/rules/ssh-brute-force' && request.method === 'GET')
      return { status: 200, body: current };
    if (path === '/rules/ssh-brute-force' && request.method === 'PUT') {
      current = {
        ...current,
        source_yaml: (request.body as { source_yaml: string }).source_yaml,
        version: current.version + 1,
        modified: true,
      };
      return { status: 200, body: current };
    }
    if (path === '/rules/validate')
      return {
        status: 200,
        body: {
          valid: true,
          error: null,
          id: rule.id,
          title: rule.title,
          rule_type: rule.rule_type,
        },
      };
    if (path === '/rules/test') return { status: 200, body: TEST_RESULT };
    if (path === '/ingest/info')
      return {
        status: 200,
        body: {
          parsers: [
            { name: 'linux_auth', label: 'Linux auth.log', description: '', input_format: 'lines' },
          ],
          max_upload_bytes: 1,
          watch_enabled: true,
          watch_interval_seconds: 10,
        },
      };
    return undefined;
  });
}

describe('RuleDetailPage', () => {
  it('explains the rule', async () => {
    stubRule(ruleDetail());

    renderAt('/rules/ssh-brute-force');

    expect(await screen.findByRole('heading', { name: 'SSH brute force' })).toBeInTheDocument();
    expect(screen.getByText('Many failed SSH logins from one address.')).toBeInTheDocument();
    expect(screen.getByText('Users retrying an expired password')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'T1110.001' })).toHaveAttribute(
      'href',
      'https://attack.mitre.org/techniques/T1110/001/',
    );
    expect(screen.getByRole('link', { name: '1 / 2' })).toHaveAttribute(
      'href',
      '/alerts?rule=ssh-brute-force',
    );
  });

  it('saves an edited definition and resets the editor to the saved version', async () => {
    const user = userEvent.setup();
    const captured: Captured[] = [];
    stubRule(ruleDetail(), captured);
    renderAt('/rules/ssh-brute-force');

    const editor = await screen.findByLabelText('Rule YAML');
    const save = screen.getByRole('button', { name: 'Save changes' });
    expect(save).toBeDisabled();

    await user.clear(editor);
    // Paste rather than type: typing the whole definition key by key is slow enough to time out.
    await user.paste(RULE_YAML.replace('count: 10', 'count: 20'));
    expect(screen.getByText(/marks this built-in rule as edited/)).toBeInTheDocument();
    await user.click(save);

    const put = captured.find((request) => request.method === 'PUT');
    expect(put?.body).toEqual({ source_yaml: expect.stringContaining('count: 20') as unknown });
    expect(await screen.findByText(/\(edited built-in\)/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
  });

  it('validates and reports save errors', async () => {
    const user = userEvent.setup();
    stubRule(ruleDetail(), [], {
      'PUT /rules/ssh-brute-force': {
        status: 422,
        body: { detail: 'severity: Input should be low, medium, ...' },
      },
    });
    renderAt('/rules/ssh-brute-force');

    await user.click(await screen.findByRole('button', { name: 'Validate' }));
    expect(await screen.findByText('The rule is valid.')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Rule YAML'), 'x');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('severity: Input should be');

    await user.click(screen.getByRole('button', { name: 'Discard' }));
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
  });

  it('tests the current draft against pasted logs', async () => {
    const user = userEvent.setup();
    const captured: Captured[] = [];
    stubRule(ruleDetail(), captured);
    renderAt('/rules/ssh-brute-force');

    const panel = await screen.findByRole('region', { name: 'Test against sample logs' });
    await user.type(
      within(panel).getByLabelText('Sample logs'),
      'Oct 12 09:00:00 web-01 sshd: Failed password',
    );
    await user.click(within(panel).getByRole('button', { name: 'Run test' }));

    expect(await within(panel).findByText('The rule fired once.')).toBeInTheDocument();
    expect(within(panel).getByText('SSH brute force: 203.0.113.45')).toBeInTheDocument();
    expect(within(panel).getByText(/lines 1, 2, 3/)).toBeInTheDocument();
    expect(within(panel).getByText('ssh_login')).toHaveAttribute('data-outcome', 'failure');
    const request = captured.find((item) => item.path === '/rules/test');
    expect(request?.body).toEqual({
      source_yaml: RULE_YAML,
      sample: 'Oct 12 09:00:00 web-01 sshd: Failed password',
      parser: 'auto',
    });
  });

  it('shows test errors such as an unknown log format', async () => {
    const user = userEvent.setup();
    stubRule(ruleDetail(), [], {
      'POST /rules/test': {
        status: 422,
        body: { detail: 'could not recognise the log format automatically' },
      },
    });
    renderAt('/rules/ssh-brute-force');

    const panel = await screen.findByRole('region', { name: 'Test against sample logs' });
    await user.type(within(panel).getByLabelText('Sample logs'), 'shopping list');
    await user.click(within(panel).getByRole('button', { name: 'Run test' }));

    expect(await within(panel).findByRole('alert')).toHaveTextContent('could not recognise');
  });

  it('reports a missing rule', async () => {
    stubApi(() => ({ status: 404, body: { detail: "rule 'gone' not found" } }));

    renderAt('/rules/gone');

    expect(await screen.findByText("rule 'gone' not found")).toBeInTheDocument();
  });
});
