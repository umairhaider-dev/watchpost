import { useIngestionJob } from '../../api/queries';
import { formatNumber } from '../../lib/format';

export function JobDetails({ id }: { id: number }) {
  const job = useIngestionJob(id);

  if (job.isPending) return <p className="muted">Loading job details…</p>;
  if (job.isError) return <p className="text-error">Could not load this job.</p>;

  const detail = job.data;
  return (
    <div className="job-details">
      {detail.error ? (
        <p className="text-error" role="alert">
          {detail.error}
        </p>
      ) : null}
      <dl className="stat-row">
        <div>
          <dt>Records read</dt>
          <dd>{formatNumber(detail.records_read)}</dd>
        </div>
        <div>
          <dt>Inserted</dt>
          <dd>{formatNumber(detail.events_inserted)}</dd>
        </div>
        <div>
          <dt>Duplicates</dt>
          <dd>{formatNumber(detail.events_duplicate)}</dd>
        </div>
        <div>
          <dt>Malformed</dt>
          <dd>{formatNumber(detail.records_malformed)}</dd>
        </div>
        <div>
          <dt>Host override</dt>
          <dd>{detail.host_name ?? '—'}</dd>
        </div>
      </dl>

      {detail.malformed_samples.length > 0 ? (
        <>
          <h3 className="subheading">
            Malformed records
            {detail.records_malformed > detail.malformed_samples.length
              ? ` (first ${String(detail.malformed_samples.length)} of ${formatNumber(detail.records_malformed)})`
              : null}
          </h3>
          <table className="table table--compact">
            <thead>
              <tr>
                <th scope="col">Line</th>
                <th scope="col">Reason</th>
                <th scope="col">Content</th>
              </tr>
            </thead>
            <tbody>
              {detail.malformed_samples.map((sample) => (
                <tr key={sample.line}>
                  <td className="mono">{sample.line}</td>
                  <td>{sample.reason}</td>
                  <td className="mono excerpt">{sample.excerpt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : detail.status === 'completed' ? (
        <p className="muted">No malformed records.</p>
      ) : null}
    </div>
  );
}
