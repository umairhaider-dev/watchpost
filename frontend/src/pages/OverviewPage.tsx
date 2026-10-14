import { useId, useState } from 'react';
import { Link } from 'react-router';

import { DASHBOARD_RANGES, useDashboard } from '../api/dashboard';
import type { Dashboard, DashboardRange, Resolution, Severity } from '../api/types';
import { Card } from '../components/Card';
import { BarList } from '../components/charts/BarList';
import { type Column, ColumnChart } from '../components/charts/ColumnChart';
import { EntityLink } from '../components/EntityLink';
import { PageHeader } from '../components/PageHeader';
import { PlatformHealth } from '../components/PlatformHealth';
import { SeverityBadge } from '../components/SeverityBadge';
import { formatNumber, formatSeconds } from '../lib/format';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

function alertColumns(board: Dashboard): Column[] {
  return board.alerts_over_time.map((bucket) => ({
    start: bucket.bucket,
    // Bottom to top: the most severe alerts sit on the baseline.
    segments: SEVERITY_ORDER.map((severity) => ({
      key: severity,
      label: severity,
      value: bucket[severity],
      className: `chart__seg chart__seg--${severity}`,
    })),
  }));
}

function ingestionColumns(board: Dashboard): Column[] {
  return board.ingestion.series.map((bucket) => ({
    start: bucket.bucket,
    segments: [
      {
        key: 'events',
        label: 'events',
        value: bucket.events,
        className: 'chart__seg chart__seg--events',
      },
    ],
  }));
}

function Headline({ board }: { board: Dashboard }) {
  const { totals } = board;
  return (
    <Card title="At a glance">
      <dl className="stat-row stat-row--wide">
        <div>
          <dt>Open alerts</dt>
          <dd>
            <Link className="link" to="/alerts">
              {formatNumber(totals.open_alerts)}
            </Link>
          </dd>
        </div>
        <div>
          <dt>New, not yet triaged</dt>
          <dd>{formatNumber(totals.new_alerts)}</dd>
        </div>
        <div>
          <dt>Open and unassigned</dt>
          <dd>{formatNumber(totals.unassigned_open_alerts)}</dd>
        </div>
        <div>
          <dt>Open cases</dt>
          <dd>
            <Link className="link" to="/cases">
              {formatNumber(totals.open_cases)}
            </Link>
          </dd>
        </div>
        <div>
          <dt>Alerts in period</dt>
          <dd>{formatNumber(totals.alerts)}</dd>
        </div>
        <div>
          <dt>Events stored</dt>
          <dd>{formatNumber(totals.events)}</dd>
        </div>
      </dl>
    </Card>
  );
}

function ResolutionFacts({ title, resolution }: { title: string; resolution: Resolution }) {
  return (
    <div>
      <h3 className="subheading">{title}</h3>
      <dl className="stat-row">
        <div>
          <dt>Mean</dt>
          <dd>{formatSeconds(resolution.mean_seconds)}</dd>
        </div>
        <div>
          <dt>Median</dt>
          <dd>{formatSeconds(resolution.median_seconds)}</dd>
        </div>
        <div>
          <dt>Resolved</dt>
          <dd>{formatNumber(resolution.resolved)}</dd>
        </div>
      </dl>
    </div>
  );
}

function DashboardCards({ board }: { board: Dashboard }) {
  const { ingestion } = board;
  return (
    <div className="dashboard-grid">
      <Headline board={board} />
      <div className="dashboard-grid__wide">
        <Card
          title="Alerts over time"
          aside={
            <ul className="chart__legend small" aria-label="Severity colours">
              {SEVERITY_ORDER.map((severity) => (
                <li key={severity} data-tone={severity}>
                  {severity}
                </li>
              ))}
            </ul>
          }
        >
          <ColumnChart
            columns={alertColumns(board)}
            bucketSeconds={board.bucket_seconds}
            label="Alerts over time"
            unit="alerts"
            emptyText="No alerts in this period."
          />
        </Card>
      </div>
      <Card title="Alerts by severity">
        <BarList
          label="Alerts by severity"
          emptyText="No alerts in this period."
          items={board.alerts_by_severity.map((row) => ({
            key: row.severity,
            tone: row.severity,
            value: row.count,
            label: (
              <Link className="link" to={`/alerts?severity=${row.severity}`}>
                <SeverityBadge severity={row.severity} />
              </Link>
            ),
            detail: row.count ? `${formatNumber(row.open)} still open` : undefined,
          }))}
        />
      </Card>
      <Card title="Top attacking IPs">
        <BarList
          label="Source addresses with the most alerts"
          emptyText="No alerts with a source address in this period."
          items={board.top_source_ips.map((ip) => ({
            key: ip.value,
            value: ip.alerts,
            label: (
              <>
                <EntityLink kind="ip" value={ip.value} />
                {ip.known_bad ? (
                  <span className="ioc-flag" title="In the threat intel store">
                    IOC
                  </span>
                ) : null}
              </>
            ),
            detail: `${formatNumber(ip.events)} events`,
          }))}
        />
      </Card>
      <Card title="Top targeted users">
        <BarList
          label="Users with the most alerts"
          emptyText="No alerts naming a user in this period."
          items={board.top_users.map((user) => ({
            key: user.value,
            value: user.alerts,
            label: <EntityLink kind="user" value={user.value} />,
            detail: `${formatNumber(user.events)} events`,
          }))}
        />
      </Card>
      <Card title="Top triggered rules">
        <BarList
          label="Rules that raised the most alerts"
          emptyText="No rule fired in this period."
          items={board.top_rules.map((rule) => ({
            key: rule.rule_id,
            value: rule.alerts,
            tone: rule.severity,
            label: (
              <Link className="link" to={`/alerts?rule=${rule.rule_id}`}>
                {rule.title}
              </Link>
            ),
          }))}
        />
      </Card>
      <Card title="Ingestion rate">
        <ColumnChart
          columns={ingestionColumns(board)}
          bucketSeconds={board.bucket_seconds}
          label="Events stored over time"
          unit="events"
          emptyText="Nothing ingested in this period."
        />
        <p className="muted small">
          {formatNumber(ingestion.events_ingested)} events stored by {formatNumber(ingestion.jobs)}{' '}
          {ingestion.jobs === 1 ? 'job' : 'jobs'}
          {ingestion.events_per_second !== null
            ? `, ${formatNumber(Math.round(ingestion.events_per_second))} events/s on average while running`
            : ''}
          .
        </p>
      </Card>
      <Card title="Time to resolve">
        <ResolutionFacts title="Cases (opened to resolved)" resolution={board.case_resolution} />
        <ResolutionFacts title="Alerts (raised to resolved)" resolution={board.alert_resolution} />
      </Card>
    </div>
  );
}

export function OverviewPage() {
  const [range, setRange] = useState<DashboardRange>('7d');
  const board = useDashboard(range);
  const rangeId = useId();

  return (
    <>
      <PageHeader
        title="Overview"
        description="Detections, investigations and ingestion at a glance. Alerts count by when their activity started."
      />
      <div className="inline-field page-toolbar">
        <label htmlFor={rangeId} className="muted small">
          Period
        </label>
        <select
          id={rangeId}
          value={range}
          onChange={(event) => {
            setRange(event.target.value as DashboardRange);
          }}
        >
          {DASHBOARD_RANGES.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </div>
      {board.isPending ? <p className="muted">Loading the dashboard…</p> : null}
      {board.isError ? (
        <p className="text-error" role="alert">
          Could not load the dashboard: {board.error.message}
        </p>
      ) : null}
      {board.data ? <DashboardCards board={board.data} /> : null}
      <h2 className="section-title">Platform health</h2>
      <PlatformHealth />
    </>
  );
}
