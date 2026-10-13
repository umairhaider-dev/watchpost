import type { IngestInfo } from '../../api/types';
import { Card } from '../Card';
import { StatusIndicator } from '../StatusIndicator';

export function WatchFolderCard({ info }: { info: IngestInfo | undefined }) {
  const enabled = info?.watch_enabled ?? false;

  return (
    <Card
      title="Watched folder"
      aside={
        info ? (
          <StatusIndicator
            tone={enabled ? 'ok' : 'unknown'}
            label={enabled ? 'Active' : 'Disabled'}
          />
        ) : null
      }
    >
      {enabled && info ? (
        <>
          <p>
            Copy log files into the <code>watch/</code> folder next to{' '}
            <code>docker-compose.yml</code>. The worker checks it every{' '}
            {info.watch_interval_seconds} seconds and ingests each new or changed file once.
          </p>
          <p className="muted small">
            To force a format, put the file in a subfolder named after the parser:{' '}
            {info.parsers.map((parser, index) => (
              <span key={parser.name}>
                {index > 0 ? ', ' : null}
                <code>{parser.name}/</code>
              </span>
            ))}
            .
          </p>
        </>
      ) : (
        <p className="muted">The folder watcher is turned off (WATCHPOST_WATCH_ENABLED=false).</p>
      )}
    </Card>
  );
}
