import type { Activity } from '../api/types';
import { formatUtc } from '../lib/format';
import { describeActivity } from '../lib/labels';

/** The audit history of an alert or case, oldest first. */
export function ActivityList({ entries }: { entries: Activity[] }) {
  if (entries.length === 0) return <p className="muted small">Nothing recorded yet.</p>;
  return (
    <ol className="activity">
      {entries.map((entry) => (
        <li key={entry.id}>
          <span className="mono small muted">{formatUtc(entry.occurred_at)}</span>{' '}
          <strong>{entry.username ?? 'Someone'}</strong> {describeActivity(entry)}
        </li>
      ))}
    </ol>
  );
}
