import { useId, useState } from 'react';

import { useDetectionRuns, useStartDetectionRun } from '../../api/queries';
import type { DetectionRun } from '../../api/types';
import { formatNumber, formatUtc } from '../../lib/format';
import { Card } from '../Card';
import { JobStatusBadge } from '../JobStatusBadge';

const RANGES = [
  { value: '24h', label: 'Last 24 hours', hours: 24 },
  { value: '7d', label: 'Last 7 days', hours: 24 * 7 },
  { value: '30d', label: 'Last 30 days', hours: 24 * 30 },
  { value: 'all', label: 'All stored events', hours: null },
] as const;

type RangeValue = (typeof RANGES)[number]['value'];

function describeScope(run: DetectionRun): string {
  if (run.ingest_job_id !== null) return `ingestion job #${String(run.ingest_job_id)}`;
  if (run.trigger === 'intel') return 'events matching new threat intel';
  if (run.range_start) return `since ${formatUtc(run.range_start)}`;
  return 'all stored events';
}

export function DetectionRunsCard() {
  const runs = useDetectionRuns();
  const start = useStartDetectionRun();
  const [range, setRange] = useState<RangeValue>('7d');
  const selectId = useId();

  function startRun() {
    const hours = RANGES.find((option) => option.value === range)?.hours ?? null;
    const payload =
      hours === null ? {} : { start: new Date(Date.now() - hours * 3_600_000).toISOString() };
    start.mutate(payload);
  }

  return (
    <Card title="Detection runs">
      <p className="muted small">
        New uploads are scanned automatically. Run the enabled rules over stored events after
        enabling or editing a rule.
      </p>
      <div className="inline-field">
        <label htmlFor={selectId} className="muted small">
          Scan
        </label>
        <select
          id={selectId}
          value={range}
          onChange={(event) => {
            setRange(event.target.value as RangeValue);
          }}
        >
          {RANGES.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <button type="button" className="button" disabled={start.isPending} onClick={startRun}>
          {start.isPending ? 'Starting…' : 'Run detection'}
        </button>
      </div>
      {start.isError ? (
        <p className="text-error" role="alert">
          {start.error.message}
        </p>
      ) : null}
      {runs.data && runs.data.length > 0 ? (
        <ul className="run-list">
          {runs.data.map((run) => (
            <li key={run.id}>
              <JobStatusBadge status={run.status} />
              <span>
                #{run.id} · {describeScope(run)}
              </span>
              <span className="muted small">
                {formatNumber(run.events_scanned)} events · {run.alerts_created} new,{' '}
                {run.alerts_updated} updated alerts
              </span>
              {run.error ? <span className="text-error small">{run.error}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </Card>
  );
}
