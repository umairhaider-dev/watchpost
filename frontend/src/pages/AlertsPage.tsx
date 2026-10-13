import { Fragment, useId, useState } from 'react';
import { Link, useSearchParams } from 'react-router';

import { type AlertFilters, useAlert, useAlerts } from '../api/queries';
import type { AlertStatus, Severity } from '../api/types';
import { Card } from '../components/Card';
import { PageHeader } from '../components/PageHeader';
import { SeverityBadge } from '../components/SeverityBadge';
import { formatNumber, formatUtc } from '../lib/format';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];
const STATUSES: { value: AlertStatus | ''; label: string }[] = [
  { value: '', label: 'Any status' },
  { value: 'new', label: 'New' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'true_positive', label: 'True positive' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'closed', label: 'Closed' },
];
const COLUMN_COUNT = 7;

function AlertEvidence({ id }: { id: number }) {
  const alert = useAlert(id);
  if (alert.isPending) return <p className="muted">Loading evidence…</p>;
  if (alert.isError) return <p className="text-error">Could not load this alert.</p>;
  const detail = alert.data;

  return (
    <div className="event-details">
      {detail.rule ? <p className="prose small">{detail.rule.description}</p> : null}
      <h3 className="subheading">
        Evidence ({detail.evidence.length} of {formatNumber(detail.event_count)} events)
      </h3>
      <div className="table-wrap">
        <table className="table table--compact">
          <thead>
            <tr>
              <th scope="col">Time</th>
              <th scope="col">Source</th>
              <th scope="col">User</th>
              <th scope="col">Source IP</th>
              <th scope="col">Action</th>
              <th scope="col">Details</th>
            </tr>
          </thead>
          <tbody>
            {detail.evidence.map((event) => (
              <tr key={event.id}>
                <td className="mono nowrap">{formatUtc(event.timestamp)}</td>
                <td>
                  <span className="badge">{event.log_source}</span>
                </td>
                <td>{event.user_name ?? '—'}</td>
                <td className="mono">{event.source_ip ?? '—'}</td>
                <td>
                  <span className="action" data-outcome={event.event_outcome ?? 'unknown'}>
                    {event.event_action ?? '—'}
                  </span>
                </td>
                <td className="excerpt">
                  {event.process_command_line ?? event.url_original ?? event.message}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function AlertsPage() {
  const [searchParams] = useSearchParams();
  const ruleFilter = searchParams.get('rule') ?? '';
  const [filters, setFilters] = useState<Omit<AlertFilters, 'ruleId'>>({
    severity: [],
    status: '',
  });
  const [expanded, setExpanded] = useState<number | null>(null);
  const alerts = useAlerts({ ...filters, ruleId: ruleFilter });
  const statusId = useId();
  const items = alerts.data?.items ?? [];

  function toggleSeverity(severity: Severity) {
    setFilters((current) => ({
      ...current,
      severity: current.severity.includes(severity)
        ? current.severity.filter((value) => value !== severity)
        : [...current.severity, severity],
    }));
  }

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Detections grouped by rule and entity: repeated activity updates one open alert instead of creating new ones."
      />
      <Card
        title={ruleFilter ? `Alerts from ${ruleFilter}` : 'Alert queue'}
        aside={
          alerts.data ? <span className="muted">{formatNumber(alerts.data.total)}</span> : null
        }
      >
        <div className="filter-bar">
          <div className="chip-group" role="group" aria-label="Severity">
            {SEVERITIES.map((severity) => (
              <button
                key={severity}
                type="button"
                className="chip"
                aria-pressed={filters.severity.includes(severity)}
                onClick={() => {
                  toggleSeverity(severity);
                }}
              >
                {severity}
              </button>
            ))}
          </div>
          <div className="inline-field">
            <label htmlFor={statusId} className="muted small">
              Status
            </label>
            <select
              id={statusId}
              value={filters.status}
              onChange={(event) => {
                setFilters((current) => ({
                  ...current,
                  status: event.target.value as AlertStatus | '',
                }));
              }}
            >
              {STATUSES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          {ruleFilter ? (
            <Link className="link small" to="/alerts">
              Show alerts from every rule
            </Link>
          ) : null}
        </div>
        {alerts.isPending ? <p className="muted">Loading alerts…</p> : null}
        {alerts.isError ? <p className="text-error">Could not load alerts.</p> : null}
        {alerts.isSuccess && items.length === 0 ? (
          <p className="muted">No alerts match these filters.</p>
        ) : null}
        {items.length > 0 ? (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Alert</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Entity</th>
                  <th scope="col" className="numeric">
                    Events
                  </th>
                  <th scope="col">First seen</th>
                  <th scope="col">Last seen</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {items.map((alert) => {
                  const isOpen = expanded === alert.id;
                  return (
                    <Fragment key={alert.id}>
                      <tr className={isOpen ? 'is-open' : undefined}>
                        <td>
                          <button
                            type="button"
                            className="row-toggle"
                            aria-expanded={isOpen}
                            onClick={() => {
                              setExpanded(isOpen ? null : alert.id);
                            }}
                          >
                            <span className="row-toggle__chevron" aria-hidden="true" />
                            <span>{alert.title}</span>
                          </button>
                          <span className="muted small origin">
                            #{alert.id} · {alert.mitre_techniques.join(', ')}
                          </span>
                        </td>
                        <td>
                          <SeverityBadge severity={alert.severity} />
                        </td>
                        <td className="small">
                          {[alert.host_name, alert.user_name, alert.source_ip]
                            .filter(Boolean)
                            .join(' · ') || '—'}
                        </td>
                        <td className="numeric">{formatNumber(alert.event_count)}</td>
                        <td className="mono nowrap small">{formatUtc(alert.first_seen)}</td>
                        <td className="mono nowrap small">{formatUtc(alert.last_seen)}</td>
                        <td>
                          <span className="pill" data-alert-status={alert.status}>
                            {alert.status.replace('_', ' ')}
                          </span>
                        </td>
                      </tr>
                      {isOpen ? (
                        <tr className="row-details">
                          <td colSpan={COLUMN_COUNT}>
                            <AlertEvidence id={alert.id} />
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
    </>
  );
}
