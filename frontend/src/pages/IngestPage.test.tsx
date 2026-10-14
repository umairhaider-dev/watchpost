import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ApiError, uploadLogFile } from '../api/client';
import type { IngestInfo, IngestionJob, IngestionJobDetail } from '../api/types';
import { renderAt, stubApi } from '../test/utils';

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>();
  return { ...actual, uploadLogFile: vi.fn() };
});

const INFO: IngestInfo = {
  parsers: [
    {
      name: 'linux_auth',
      label: 'Linux auth.log',
      description: 'Syslog auth logs.',
      input_format: 'lines',
    },
    {
      name: 'windows',
      label: 'Windows event log (JSON)',
      description: 'Windows events.',
      input_format: 'json',
    },
  ],
  max_upload_bytes: 1024,
  watch_enabled: true,
  watch_interval_seconds: 10,
};

function job(overrides: Partial<IngestionJob> = {}): IngestionJob {
  return {
    id: 7,
    origin: 'upload',
    status: 'completed',
    filename: 'malformed_lines.log',
    parser: 'auto',
    detected_parser: 'linux_auth',
    host_name: null,
    file_size: 600,
    bytes_processed: 600,
    records_read: 7,
    events_inserted: 4,
    events_duplicate: 0,
    records_malformed: 3,
    records_skipped: 0,
    error: null,
    created_at: '2026-10-12T09:00:00Z',
    started_at: '2026-10-12T09:00:00Z',
    finished_at: '2026-10-12T09:00:01Z',
    ...overrides,
  };
}

const DETAIL: IngestionJobDetail = {
  ...job(),
  malformed_samples: [
    { line: 2, reason: 'not a syslog line', excerpt: 'this line is not syslog at all' },
  ],
};

let jobs: IngestionJob[];

beforeEach(() => {
  jobs = [job()];
  stubApi((path) => {
    if (path === '/health')
      return { status: 200, body: { status: 'ok', version: '0.2.0', environment: 'test' } };
    if (path === '/ingest/info') return { status: 200, body: INFO };
    if (path === '/ingest/jobs') return { status: 200, body: { items: jobs, total: jobs.length } };
    if (path === '/ingest/jobs/7') return { status: 200, body: DETAIL };
    return undefined;
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.mocked(uploadLogFile).mockReset();
});

describe('IngestPage', () => {
  it('lists jobs and reveals malformed lines on demand', async () => {
    const user = userEvent.setup();
    renderAt('/ingest');

    const jobsCard = await screen.findByRole('region', { name: 'Ingestion jobs' });
    const toggle = await within(jobsCard).findByRole('button', { name: /malformed_lines\.log/ });
    expect(within(jobsCard).getByText('Completed')).toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-expanded', 'false');

    await user.click(toggle);

    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(await screen.findByText('this line is not syslog at all')).toBeInTheDocument();
    expect(screen.getByText('not a syslog line')).toBeInTheDocument();
  });

  it('offers every parser and explains the watched folder', async () => {
    renderAt('/ingest');

    const select = await screen.findByLabelText('Format');
    expect(
      await within(select).findByRole('option', { name: 'Linux auth.log' }),
    ).toBeInTheDocument();
    expect(
      within(select).getByRole('option', { name: 'Detect automatically' }),
    ).toBeInTheDocument();
    expect(await screen.findByText(/checks it every 10 seconds/)).toBeInTheDocument();
  });

  it('uploads the chosen file with the selected options', async () => {
    const user = userEvent.setup();
    vi.mocked(uploadLogFile).mockImplementation((file, options) => {
      options.onProgress?.(1);
      const queued = job({ id: 8, status: 'queued', filename: file.name });
      jobs = [queued, ...jobs];
      return Promise.resolve(queued);
    });
    renderAt('/ingest');

    await user.upload(await screen.findByLabelText('Log file'), new File(['line\n'], 'auth.log'));
    await user.selectOptions(await screen.findByLabelText('Format'), 'linux_auth');
    await user.type(screen.getByLabelText('Host name (optional)'), 'web-01');
    await user.click(screen.getByRole('button', { name: 'Upload and ingest' }));

    expect(await screen.findByRole('status')).toHaveTextContent('Queued auth.log as job #8.');
    const [file, options] = vi.mocked(uploadLogFile).mock.calls[0] ?? [];
    expect(file?.name).toBe('auth.log');
    expect(options).toMatchObject({ parser: 'linux_auth', hostName: 'web-01' });
    expect(await screen.findByText('Queued')).toBeInTheDocument();
  });

  it('shows the reason when the server rejects a file', async () => {
    const user = userEvent.setup();
    vi.mocked(uploadLogFile).mockRejectedValue(
      new ApiError(415, 'the file looks binary (it contains NUL bytes), not like a text log'),
    );
    renderAt('/ingest');

    await user.upload(await screen.findByLabelText('Log file'), new File(['MZ'], 'tool.exe'));
    await user.click(screen.getByRole('button', { name: 'Upload and ingest' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('the file looks binary');
  });

  it('refuses files over the size limit before uploading', async () => {
    const user = userEvent.setup();
    renderAt('/ingest');
    await screen.findByText(/up to 1.0 KB/);

    await user.upload(
      await screen.findByLabelText('Log file'),
      new File(['x'.repeat(2048)], 'big.log'),
    );

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'larger than the 1.0 KB upload limit',
    );
    expect(screen.getByRole('button', { name: 'Upload and ingest' })).toBeDisabled();
    expect(uploadLogFile).not.toHaveBeenCalled();
  });

  it('shows failed jobs with their error', async () => {
    const user = userEvent.setup();
    jobs = [
      job({ status: 'failed', error: 'could not recognise the log format', records_malformed: 0 }),
    ];
    renderAt('/ingest');

    await user.click(await screen.findByRole('button', { name: /malformed_lines\.log/ }));

    expect(await screen.findByText('Failed')).toBeInTheDocument();
  });

  it('shows what detection found for each job', async () => {
    const detection = {
      id: 3,
      status: 'completed' as const,
      hits: 7,
      alerts_created: 6,
      alerts_updated: 1,
    };
    jobs = [
      job({ id: 7, detection }),
      job({
        id: 8,
        filename: 'quiet.log',
        detection: { ...detection, alerts_created: 0, alerts_updated: 0 },
      }),
      job({ id: 9, filename: 'pending.log', detection: { ...detection, status: 'running' } }),
    ];
    renderAt('/ingest');

    expect(await screen.findByRole('link', { name: '6 new, 1 updated' })).toHaveAttribute(
      'href',
      '/alerts',
    );
    expect(screen.getByText('none')).toBeInTheDocument();
    expect(screen.getByText('Running')).toBeInTheDocument();
  });
});
