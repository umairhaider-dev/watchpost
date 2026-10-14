import { useIntelSummary, useSweepIndicators } from '../../api/queries';
import type { IocType } from '../../api/types';
import { formatNumber } from '../../lib/format';
import { IOC_TYPE_LABELS } from '../../lib/intel';
import { Card } from '../Card';

export function IntelStatsCard() {
  const summary = useIntelSummary();
  const sweep = useSweepIndicators();
  const data = summary.data;
  const byType = data
    ? (Object.entries(data.by_type) as [IocType, number][])
        .map(([type, count]) => `${formatNumber(count)} ${IOC_TYPE_LABELS[type]}`)
        .join(' · ')
    : '';

  return (
    <Card title="Indicator store">
      {summary.isPending ? <p className="muted">Loading…</p> : null}
      {summary.isError ? <p className="text-error">Could not load the indicator store.</p> : null}
      {data ? (
        <>
          <dl className="stat-row">
            <div>
              <dt>Indicators</dt>
              <dd>{formatNumber(data.total)}</dd>
            </div>
            <div>
              <dt>Active</dt>
              <dd>{formatNumber(data.active)}</dd>
            </div>
            <div>
              <dt>Seen in events</dt>
              <dd>{formatNumber(data.indicators_matched)}</dd>
            </div>
            <div>
              <dt>Flagged events</dt>
              <dd>{formatNumber(data.matched_events)}</dd>
            </div>
          </dl>
          {byType ? <p className="muted small">{byType}</p> : null}
        </>
      ) : null}
      <div className="inline-field">
        <button
          type="button"
          className="button button--secondary"
          disabled={sweep.isPending}
          onClick={() => {
            sweep.mutate();
          }}
        >
          Re-check stored events
        </button>
        {sweep.isSuccess ? (
          <span className="muted small" role="status">
            Queued: every stored event will be checked against the active indicators.
          </span>
        ) : null}
        {sweep.isError ? (
          <span className="text-error small" role="alert">
            {sweep.error.message}
          </span>
        ) : null}
      </div>
    </Card>
  );
}
