import type { IngestStatus } from '../api/types';

const LABELS: Record<IngestStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
};

export function JobStatusBadge({ status }: { status: IngestStatus }) {
  return (
    <span className="pill" data-status={status}>
      {LABELS[status]}
    </span>
  );
}
