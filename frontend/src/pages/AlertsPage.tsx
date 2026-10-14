import { type SubmitEvent, useId, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';

import { usePermissions } from '../api/auth';
import { useAssignableUsers, useBulkUpdateAlerts } from '../api/investigation';
import {
  type AlertFilters,
  type AlertSort,
  DEFAULT_ALERT_FILTERS,
  useAlerts,
} from '../api/queries';
import type { AlertStatus, BulkAlertResult, Severity } from '../api/types';
import { AssigneeSelect } from '../components/AssigneeSelect';
import { Card } from '../components/Card';
import { AddToCaseForm } from '../components/cases/AddToCaseForm';
import { EntityLink } from '../components/EntityLink';
import { PageHeader } from '../components/PageHeader';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertStatusBadge } from '../components/StatusBadges';
import { TimeRangeSelect } from '../components/TimeRangeSelect';
import { formatNumber, formatUtc } from '../lib/format';
import { ALERT_STATUSES } from '../lib/labels';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];
const SORTS: { value: AlertSort; label: string }[] = [
  { value: 'last_seen', label: 'Latest activity' },
  { value: 'severity', label: 'Severity' },
  { value: 'first_seen', label: 'First seen' },
];

type TextFilter = 'host' | 'sourceIp' | 'user' | 'technique';
const TEXT_FILTERS: { key: TextFilter; label: string; placeholder: string; param: string }[] = [
  { key: 'host', label: 'Host', placeholder: 'web-01', param: 'host' },
  { key: 'sourceIp', label: 'Source IP', placeholder: '203.0.113.45', param: 'source_ip' },
  { key: 'user', label: 'User', placeholder: 'root', param: 'user' },
  { key: 'technique', label: 'Technique', placeholder: 'T1110', param: 'technique' },
];

const STATUS_VALUES = new Set<string>(ALERT_STATUSES.map((option) => option.value));

function filtersFromUrl(params: URLSearchParams): AlertFilters {
  const filters: AlertFilters = {
    ...DEFAULT_ALERT_FILTERS,
    ruleId: params.get('rule') ?? '',
    severity: params
      .getAll('severity')
      .filter((value): value is Severity => (SEVERITIES as string[]).includes(value)),
    status: params
      .getAll('status')
      .filter((value): value is AlertStatus => STATUS_VALUES.has(value)),
  };
  for (const { key, param } of TEXT_FILTERS) filters[key] = params.get(param) ?? '';
  return filters;
}

function toggle<T>(values: T[], value: T): T[] {
  return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
}

function BulkSummary({ result }: { result: BulkAlertResult }) {
  return (
    <p className="small" role="status">
      <span className="text-ok">{result.updated.length} updated</span>
      {result.unchanged.length ? `, ${String(result.unchanged.length)} already set` : ''}
      {result.conflicts.length ? (
        <span className="text-warn">
          , {result.conflicts.length} not reopened because a newer alert is open (
          {result.conflicts.map((conflict) => `#${String(conflict.open_alert_id)}`).join(', ')})
        </span>
      ) : null}
    </p>
  );
}

function BulkActions({ alertIds, onDone }: { alertIds: number[]; onDone: () => void }) {
  const bulk = useBulkUpdateAlerts();
  const [status, setStatus] = useState<AlertStatus | ''>('');
  const statusId = useId();

  return (
    <div className="bulk-bar" aria-label="Bulk actions">
      <strong className="small">{alertIds.length} selected</strong>
      <div className="inline-field">
        <label htmlFor={statusId} className="muted small">
          Set status
        </label>
        <select
          id={statusId}
          value={status}
          onChange={(event) => {
            setStatus(event.target.value as AlertStatus | '');
          }}
        >
          <option value="">Choose…</option>
          {ALERT_STATUSES.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="button button--small"
          disabled={!status || bulk.isPending}
          onClick={() => {
            if (status) bulk.mutate({ alert_ids: alertIds, status }, { onSuccess: onDone });
          }}
        >
          Apply
        </button>
      </div>
      <AssigneeSelect
        label="Assign to"
        value={null}
        disabled={bulk.isPending}
        onChange={(assigneeId) => {
          bulk.mutate({ alert_ids: alertIds, assignee_id: assigneeId }, { onSuccess: onDone });
        }}
      />
      <AddToCaseForm alertIds={alertIds} onDone={onDone} />
      {bulk.data ? <BulkSummary result={bulk.data} /> : null}
      {bulk.isError ? (
        <span className="text-error small" role="alert">
          {bulk.error.message}
        </span>
      ) : null}
    </div>
  );
}

export function AlertsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [filters, setFilters] = useState<AlertFilters>(() => filtersFromUrl(searchParams));
  const [drafts, setDrafts] = useState(() => ({
    host: filters.host,
    sourceIp: filters.sourceIp,
    user: filters.user,
    technique: filters.technique,
  }));
  const [selected, setSelected] = useState<number[]>([]);
  const alerts = useAlerts(filters);
  const users = useAssignableUsers();
  const { canEdit } = usePermissions();
  const sortId = useId();
  const assigneeId = useId();
  const items = useMemo(() => alerts.data?.items ?? [], [alerts.data]);
  const names = new Map(users.data?.map((user) => [user.id, user.username]));
  const allSelected = items.length > 0 && items.every((alert) => selected.includes(alert.id));

  function change(next: Partial<AlertFilters>) {
    setFilters((current) => ({ ...current, ...next }));
    setSelected([]);
  }

  function applyText(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    change(drafts);
  }

  function clearAll() {
    setFilters(DEFAULT_ALERT_FILTERS);
    setDrafts({ host: '', sourceIp: '', user: '', technique: '' });
    setSearchParams({});
    setSelected([]);
  }

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Detections grouped by rule and entity: repeated activity updates one open alert instead of creating new ones."
      />
      <Card
        title={filters.ruleId ? `Alerts from ${filters.ruleId}` : 'Alert queue'}
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
                  change({ severity: toggle(filters.severity, severity) });
                }}
              >
                {severity}
              </button>
            ))}
          </div>
          <div className="chip-group" role="group" aria-label="Status">
            {ALERT_STATUSES.map((option) => (
              <button
                key={option.value}
                type="button"
                className="chip"
                aria-pressed={filters.status.includes(option.value)}
                onClick={() => {
                  change({ status: toggle(filters.status, option.value) });
                }}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
        <form className="filter-bar" onSubmit={applyText} aria-label="Entity filters">
          {TEXT_FILTERS.map(({ key, label, placeholder }) => (
            <label key={key} className="inline-field">
              <span className="muted small">{label}</span>
              <input
                type="text"
                className="filter-input"
                placeholder={placeholder}
                value={drafts[key]}
                onChange={(event) => {
                  setDrafts((current) => ({ ...current, [key]: event.target.value }));
                }}
              />
            </label>
          ))}
          <button type="submit" className="button button--small button--secondary">
            Apply
          </button>
        </form>
        <div className="filter-bar">
          <TimeRangeSelect
            label="Active in"
            value={filters.range}
            onChange={(range) => {
              change({ range });
            }}
          />
          <div className="inline-field">
            <label htmlFor={assigneeId} className="muted small">
              Assignee
            </label>
            <select
              id={assigneeId}
              value={filters.assignee}
              onChange={(event) => {
                change({ assignee: event.target.value });
              }}
            >
              <option value="">Anyone</option>
              <option value="none">Unassigned</option>
              {users.data?.map((user) => (
                <option key={user.id} value={user.id}>
                  {user.username}
                </option>
              ))}
            </select>
          </div>
          <div className="inline-field">
            <label htmlFor={sortId} className="muted small">
              Sort by
            </label>
            <select
              id={sortId}
              value={filters.sort}
              onChange={(event) => {
                change({ sort: event.target.value as AlertSort });
              }}
            >
              {SORTS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <button type="button" className="link small" onClick={clearAll}>
            Clear filters
          </button>
        </div>
        {selected.length > 0 ? (
          <BulkActions
            alertIds={selected}
            onDone={() => {
              setSelected([]);
            }}
          />
        ) : null}
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
                  {canEdit ? (
                    <th scope="col">
                      <input
                        type="checkbox"
                        aria-label="Select all alerts"
                        checked={allSelected}
                        onChange={() => {
                          setSelected(allSelected ? [] : items.map((alert) => alert.id));
                        }}
                      />
                    </th>
                  ) : null}
                  <th scope="col">Alert</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Entity</th>
                  <th scope="col" className="numeric">
                    Events
                  </th>
                  <th scope="col">Last seen</th>
                  <th scope="col">Assignee</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {items.map((alert) => (
                  <tr key={alert.id}>
                    {canEdit ? (
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Select alert ${String(alert.id)}`}
                          checked={selected.includes(alert.id)}
                          onChange={() => {
                            setSelected((current) => toggle(current, alert.id));
                          }}
                        />
                      </td>
                    ) : null}
                    <td>
                      <Link className="link" to={`/alerts/${String(alert.id)}`}>
                        {alert.title}
                      </Link>
                      <span className="muted small origin">
                        #{alert.id}
                        {alert.mitre_techniques.length
                          ? ` · ${alert.mitre_techniques.join(', ')}`
                          : ''}
                        {alert.case_id ? ` · case #${String(alert.case_id)}` : ''}
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="small entity-cell">
                      {alert.host_name ? <EntityLink kind="host" value={alert.host_name} /> : null}
                      {alert.user_name ? <EntityLink kind="user" value={alert.user_name} /> : null}
                      {alert.source_ip ? <EntityLink kind="ip" value={alert.source_ip} /> : null}
                      {!alert.host_name && !alert.user_name && !alert.source_ip ? '—' : null}
                    </td>
                    <td className="numeric">{formatNumber(alert.event_count)}</td>
                    <td className="mono nowrap small">{formatUtc(alert.last_seen)}</td>
                    <td className="small">
                      {alert.assignee_id !== null
                        ? (names.get(alert.assignee_id) ?? `#${String(alert.assignee_id)}`)
                        : '—'}
                    </td>
                    <td>
                      <AlertStatusBadge status={alert.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>
    </>
  );
}
