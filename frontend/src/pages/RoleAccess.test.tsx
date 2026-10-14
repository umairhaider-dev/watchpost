import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  alertDetail,
  alertSummary,
  analyst,
  caseDetail,
  caseSummary,
  eventRecord,
  ioc,
  ruleDetail,
  ruleSummary,
  signedInAs,
} from '../test/fixtures';
import { renderAt, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

const viewer = { user: signedInAs('viewer') };
const analystUser = { user: signedInAs('analyst') };

/** Read-only answers for every page these tests open. */
function stubReads(path: string) {
  switch (path) {
    case '/alerts':
      return { status: 200, body: { items: [alertSummary()], total: 1 } };
    case '/alerts/11':
      return { status: 200, body: alertDetail() };
    case '/cases':
      return { status: 200, body: { items: [caseSummary()], total: 1 } };
    case '/cases/7':
      return {
        status: 200,
        body: caseDetail({
          resolution: 'Password reset and source blocked.',
          evidence: [
            {
              id: 1,
              note: null,
              added_by: 'analyst.one',
              created_at: '2026-10-12T09:10:00Z',
              event: eventRecord(1),
            },
          ],
        }),
      };
    case '/users':
      return { status: 200, body: [analyst()] };
    case '/intel/iocs':
      return { status: 200, body: { items: [ioc()], total: 1 } };
    case '/rules':
      return { status: 200, body: [ruleSummary()] };
    case '/rules/ssh-brute-force':
      return { status: 200, body: ruleDetail() };
    default:
      return undefined;
  }
}

describe('viewers', () => {
  it('see alert triage without the controls to change it', async () => {
    stubApi(stubReads, viewer);
    renderAt('/alerts/11');

    const triage = await screen.findByRole('region', { name: 'Triage' });
    expect(within(triage).getByLabelText('Status')).toBeDisabled();
    expect(within(triage).getByLabelText('Assignee')).toBeDisabled();
    expect(within(triage).queryByRole('form', { name: 'Add to case' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Check indicators' })).not.toBeInTheDocument();
  });

  it('cannot select alerts for bulk changes', async () => {
    stubApi(stubReads, viewer);
    renderAt('/alerts');

    await screen.findByRole('link', { name: alertSummary().title });
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  });

  it('read cases without editing them', async () => {
    stubApi(stubReads, viewer);
    renderAt('/cases/7');

    const status = await screen.findByRole('region', { name: 'Status' });
    expect(within(status).getByLabelText('Status')).toBeDisabled();
    expect(within(status).getByLabelText('Resolution')).toHaveAttribute('readonly');
    expect(within(status).getByLabelText('Resolution')).toHaveValue(
      'Password reset and source blocked.',
    );
    expect(within(status).getByRole('link', { name: 'PDF' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^(Save resolution|Add note)$/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /^Remove alert/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Unpin event/ })).not.toBeInTheDocument();
  });

  it('cannot open cases', async () => {
    stubApi(stubReads, viewer);
    renderAt('/cases');

    await screen.findByRole('link', { name: caseSummary().title });
    expect(screen.queryByRole('region', { name: 'Open a case' })).not.toBeInTheDocument();
  });

  it('browse intel without changing it', async () => {
    stubApi(stubReads, viewer);
    renderAt('/intel');

    expect(await screen.findByRole('switch', { name: /203\.0\.113\.45/ })).toBeDisabled();
    expect(screen.queryByRole('button', { name: /^Delete/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Import a feed' })).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Add an indicator' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Re-check stored events' })).toBeNull();
    expect(screen.getByRole('region', { name: 'Look up an indicator' })).toBeInTheDocument();
  });

  it('cannot upload logs', async () => {
    stubApi(stubReads, viewer);
    renderAt('/ingest');

    expect(await screen.findByRole('heading', { name: 'Ingest' })).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Upload a log file' })).not.toBeInTheDocument();
  });

  it('cannot toggle rules or run detection', async () => {
    stubApi(stubReads, viewer);
    renderAt('/rules');

    expect(await screen.findByRole('switch', { name: 'Disable SSH brute force' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Run detection' })).not.toBeInTheDocument();
  });

  it('read rule definitions without validating or testing them', async () => {
    stubApi(stubReads, viewer);
    renderAt('/rules/ssh-brute-force');

    expect(await screen.findByLabelText('Rule YAML')).toHaveAttribute('readonly');
    expect(screen.queryByRole('button', { name: 'Validate' })).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Test against sample logs' })).toBeNull();
  });
});

describe('analysts', () => {
  it('validate and test rules but leave saving to admins', async () => {
    stubApi(stubReads, analystUser);
    renderAt('/rules/ssh-brute-force');

    const editor = await screen.findByLabelText('Rule YAML');
    expect(editor).not.toHaveAttribute('readonly');
    expect(screen.getByRole('button', { name: 'Validate' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument();
    expect(screen.getByText(/only admins can save rule changes/)).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Disable this rule' })).toBeDisabled();
    expect(screen.getByRole('region', { name: 'Test against sample logs' })).toBeInTheDocument();
  });

  it('triage alerts', async () => {
    stubApi(stubReads, analystUser);
    renderAt('/alerts/11');

    const triage = await screen.findByRole('region', { name: 'Triage' });
    expect(within(triage).getByLabelText('Status')).toBeEnabled();
    expect(within(triage).getByRole('form', { name: 'Add to case' })).toBeInTheDocument();
  });
});
