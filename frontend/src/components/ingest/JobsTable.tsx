import { Fragment, useState } from 'react';
import { Link } from 'react-router';

import { useIngestionJobs } from '../../api/queries';
import type { IngestionJob } from '../../api/types';
import { formatBytes, formatDuration, formatNumber, progressPercent } from '../../lib/format';
import { Card } from '../Card';
import { JobStatusBadge } from '../JobStatusBadge';
import { JobDetails } from './JobDetails';

const COLUMN_COUNT = 9;

function StatusCell({ job }: { job: IngestionJob }) {
  return (
    <span className="status-cell">
      <JobStatusBadge status={job.status} />
      {job.status === 'running' ? (
        <span className="muted small">{progressPercent(job.bytes_processed, job.file_size)}%</span>
      ) : null}
    </span>
  );
}

function DetectionCell({ job }: { job: IngestionJob }) {
  const run = job.detection;
  if (!run) return <span className="muted small">—</span>;
  if (run.status !== 'completed') return <JobStatusBadge status={run.status} />;
  if (run.alerts_created + run.alerts_updated === 0) {
    return <span className="muted small">none</span>;
  }
  return (
    <Link className="link small" to="/alerts">
      {run.alerts_created} new
      {run.alerts_updated > 0 ? `, ${String(run.alerts_updated)} updated` : null}
    </Link>
  );
}

export function JobsTable() {
  const jobs = useIngestionJobs();
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <Card
      title="Ingestion jobs"
      aside={jobs.data ? <span className="muted">{formatNumber(jobs.data.total)}</span> : null}
    >
      {jobs.isPending ? <p className="muted">Loading jobs…</p> : null}
      {jobs.isError ? <p className="text-error">Could not load ingestion jobs.</p> : null}
      {jobs.data?.items.length === 0 ? (
        <p className="muted">
          Nothing ingested yet. Upload a file or drop one in the watched folder.
        </p>
      ) : null}
      {jobs.data && jobs.data.items.length > 0 ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">File</th>
                <th scope="col">Format</th>
                <th scope="col">Status</th>
                <th scope="col" className="numeric">
                  Inserted
                </th>
                <th scope="col" className="numeric">
                  Duplicates
                </th>
                <th scope="col" className="numeric">
                  Malformed
                </th>
                <th scope="col">Alerts</th>
                <th scope="col" className="numeric">
                  Size
                </th>
                <th scope="col" className="numeric">
                  Duration
                </th>
              </tr>
            </thead>
            <tbody>
              {jobs.data.items.map((job) => {
                const isOpen = expanded === job.id;
                return (
                  <Fragment key={job.id}>
                    <tr className={isOpen ? 'is-open' : undefined}>
                      <td>
                        <button
                          type="button"
                          className="row-toggle"
                          aria-expanded={isOpen}
                          onClick={() => {
                            setExpanded(isOpen ? null : job.id);
                          }}
                        >
                          <span className="row-toggle__chevron" aria-hidden="true" />
                          <span className="mono">{job.filename}</span>
                        </button>
                        <span className="muted small origin">
                          {job.origin === 'upload' ? 'upload' : 'watched folder'} · #{job.id}
                        </span>
                      </td>
                      <td className="mono">{job.detected_parser ?? job.parser}</td>
                      <td>
                        <StatusCell job={job} />
                      </td>
                      <td className="numeric">{formatNumber(job.events_inserted)}</td>
                      <td className="numeric">{formatNumber(job.events_duplicate)}</td>
                      <td className="numeric" data-alert={job.records_malformed > 0}>
                        {formatNumber(job.records_malformed)}
                      </td>
                      <td>
                        <DetectionCell job={job} />
                      </td>
                      <td className="numeric">{formatBytes(job.file_size)}</td>
                      <td className="numeric">{formatDuration(job.started_at, job.finished_at)}</td>
                    </tr>
                    {isOpen ? (
                      <tr className="row-details">
                        <td colSpan={COLUMN_COUNT}>
                          <JobDetails id={job.id} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </Card>
  );
}
