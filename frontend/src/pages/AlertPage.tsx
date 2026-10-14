import { useId, useState } from 'react';
import { Link, useParams } from 'react-router';

import { usePermissions } from '../api/auth';
import { useAlertTimeline, useUpdateAlert } from '../api/investigation';
import { useAlert } from '../api/queries';
import type { AlertDetail, AlertStatus, TimelineEvent } from '../api/types';
import { ActivityList } from '../components/ActivityList';
import { AssigneeSelect } from '../components/AssigneeSelect';
import { Card } from '../components/Card';
import { AddToCaseForm } from '../components/cases/AddToCaseForm';
import { EntityLink } from '../components/EntityLink';
import { EventTable } from '../components/events/EventTable';
import { EnrichmentPanel } from '../components/intel/EnrichmentPanel';
import { PageHeader } from '../components/PageHeader';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertStatusBadge } from '../components/StatusBadges';
import { countOf, formatNumber, formatUtc } from '../lib/format';
import { ALERT_STATUSES } from '../lib/labels';
import { NotFoundPage } from './NotFoundPage';

const WINDOWS = [5, 15, 30, 60, 240, 1440];

function Triage({ alert }: { alert: AlertDetail }) {
  const update = useUpdateAlert(alert.id);
  const { canEdit } = usePermissions();
  const statusId = useId();

  return (
    <Card title="Triage">
      <div className="filter-bar">
        <div className="inline-field">
          <label htmlFor={statusId} className="muted small">
            Status
          </label>
          <select
            id={statusId}
            value={alert.status}
            disabled={!canEdit || update.isPending}
            onChange={(event) => {
              update.mutate({ status: event.target.value as AlertStatus });
            }}
          >
            {ALERT_STATUSES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <AssigneeSelect
          label="Assignee"
          value={alert.assignee_id}
          disabled={!canEdit || update.isPending}
          onChange={(assigneeId) => {
            update.mutate({ assignee_id: assigneeId });
          }}
        />
      </div>
      {update.isError ? (
        <p className="text-error small" role="alert">
          {update.error.message}
        </p>
      ) : null}
      {alert.resolved_at ? (
        <p className="muted small">Resolved {formatUtc(alert.resolved_at)}.</p>
      ) : null}
      {alert.case_id !== null ? (
        <p className="small">
          Part of{' '}
          <Link className="link" to={`/cases/${String(alert.case_id)}`}>
            case #{alert.case_id}
          </Link>
          .
        </p>
      ) : canEdit ? (
        <AddToCaseForm alertIds={[alert.id]} defaultTitle={alert.title} />
      ) : null}
    </Card>
  );
}

function Timeline({ alertId }: { alertId: number }) {
  const [windowMinutes, setWindowMinutes] = useState(30);
  const timeline = useAlertTimeline(alertId, windowMinutes);
  const windowId = useId();

  return (
    <Card
      title="Timeline"
      aside={
        <div className="inline-field">
          <label htmlFor={windowId} className="muted small">
            Window
          </label>
          <select
            id={windowId}
            value={windowMinutes}
            onChange={(event) => {
              setWindowMinutes(Number(event.target.value));
            }}
          >
            {WINDOWS.map((minutes) => (
              <option key={minutes} value={minutes}>
                {minutes < 60 ? `±${String(minutes)} min` : `±${String(minutes / 60)} h`}
              </option>
            ))}
          </select>
        </div>
      }
    >
      {timeline.isPending ? <p className="muted">Loading timeline…</p> : null}
      {timeline.isError ? <p className="text-error">Could not load the timeline.</p> : null}
      {timeline.data ? (
        <>
          <p className="muted small">
            Events from {formatUtc(timeline.data.start)} to {formatUtc(timeline.data.end)} involving{' '}
            {Object.entries(timeline.data.entities)
              .map(([field, value]) => `${field} ${value}`)
              .join(', ') || 'only the evidence'}
            .{timeline.data.truncated ? ' Only the first 500 are shown; narrow the window.' : ''}
          </p>
          {timeline.data.events.length > 0 ? (
            <EventTable<TimelineEvent>
              events={timeline.data.events}
              rowClass={(event) => (event.is_evidence ? 'is-evidence' : undefined)}
              marker={(event) =>
                event.is_evidence ? <span className="evidence-flag">Evidence</span> : null
              }
            />
          ) : (
            <p className="muted">No events in this window.</p>
          )}
        </>
      ) : null}
    </Card>
  );
}

export function AlertPage() {
  const { alertId } = useParams();
  const id = Number(alertId);
  const valid = Number.isInteger(id) && id > 0;
  const alert = useAlert(id, valid);

  if (!valid) return <NotFoundPage />;
  if (alert.isPending) return <p className="muted">Loading alert…</p>;
  if (alert.isError) {
    return (
      <>
        <PageHeader title={`Alert #${String(id)}`} />
        <p className="text-error">Could not load this alert. It may have been deleted.</p>
      </>
    );
  }
  const detail = alert.data;

  return (
    <>
      <nav className="breadcrumb small" aria-label="Breadcrumb">
        <Link className="link" to="/alerts">
          Alerts
        </Link>{' '}
        / #{detail.id}
      </nav>
      <PageHeader title={detail.title} description={detail.rule?.description} />
      <div className="grid grid--wide">
        <div className="stack stack--flush">
          <Card
            title="Details"
            aside={
              <span className="inline-field">
                <SeverityBadge severity={detail.severity} />
                <AlertStatusBadge status={detail.status} />
              </span>
            }
          >
            <dl className="facts facts--inline">
              <div>
                <dt>Rule</dt>
                <dd>
                  {detail.rule_id ? (
                    <Link className="link" to={`/rules/${detail.rule_id}`}>
                      {detail.rule?.title ?? detail.rule_id}
                    </Link>
                  ) : (
                    '—'
                  )}
                </dd>
              </div>
              <div>
                <dt>First seen</dt>
                <dd className="mono">{formatUtc(detail.first_seen)}</dd>
              </div>
              <div>
                <dt>Last seen</dt>
                <dd className="mono">{formatUtc(detail.last_seen)}</dd>
              </div>
              <div>
                <dt>Events</dt>
                <dd>{formatNumber(detail.event_count)}</dd>
              </div>
              <div>
                <dt>Host</dt>
                <dd>
                  <EntityLink kind="host" value={detail.host_name} />
                </dd>
              </div>
              <div>
                <dt>Source IP</dt>
                <dd>
                  <EntityLink kind="ip" value={detail.source_ip} />
                </dd>
              </div>
              <div>
                <dt>User</dt>
                <dd>
                  <EntityLink kind="user" value={detail.user_name} />
                </dd>
              </div>
              <div>
                <dt>ATT&amp;CK</dt>
                <dd className="tag-list">
                  {detail.mitre_techniques.length
                    ? detail.mitre_techniques.map((technique) => (
                        <Link
                          key={technique}
                          className="badge"
                          to={`/alerts?technique=${technique}`}
                        >
                          {technique}
                        </Link>
                      ))
                    : '—'}
                </dd>
              </div>
            </dl>
            {detail.rule?.false_positives.length ? (
              <>
                <h3 className="subheading">Known false positives</h3>
                <ul className="plain-list bullets small">
                  {detail.rule.false_positives.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              </>
            ) : null}
          </Card>
          <EnrichmentPanel alertId={detail.id} enrichment={detail.enrichment} />
        </div>
        <div className="stack stack--flush">
          <Triage alert={detail} />
          <Card title="Activity">
            <ActivityList entries={detail.activity} />
          </Card>
        </div>
      </div>
      <div className="stack">
        <Timeline alertId={detail.id} />
        <Card
          title={`Evidence (${String(detail.evidence.length)} of ${countOf(detail.event_count, 'event')})`}
        >
          {detail.evidence.length ? (
            <EventTable events={detail.evidence} />
          ) : (
            <p className="muted">No evidence events are linked.</p>
          )}
        </Card>
      </div>
    </>
  );
}
