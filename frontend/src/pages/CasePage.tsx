import { type SubmitEvent, useId, useState } from 'react';
import { Link, useParams } from 'react-router';

import {
  caseReportUrl,
  useAddNote,
  useCase,
  useUnlinkAlert,
  useUnpinEvidence,
  useUpdateCase,
} from '../api/investigation';
import { usePermissions } from '../api/auth';
import type { CaseDetail, CaseStatus, Severity } from '../api/types';
import { ActivityList } from '../components/ActivityList';
import { AssigneeSelect } from '../components/AssigneeSelect';
import { Card } from '../components/Card';
import { EntityLink } from '../components/EntityLink';
import { PageHeader } from '../components/PageHeader';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertStatusBadge, CaseStatusBadge } from '../components/StatusBadges';
import { eventSummary } from '../lib/events';
import { formatUtc } from '../lib/format';
import { CASE_STATUSES } from '../lib/labels';
import { NotFoundPage } from './NotFoundPage';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

function CaseControls({ detail }: { detail: CaseDetail }) {
  const update = useUpdateCase(detail.id);
  const { canEdit } = usePermissions();
  const [resolution, setResolution] = useState(detail.resolution ?? '');
  const statusId = useId();
  const severityId = useId();
  const resolutionId = useId();

  function saveResolution(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    update.mutate({ resolution: resolution.trim() || null });
  }

  return (
    <Card title="Status">
      <div className="filter-bar">
        <div className="inline-field">
          <label htmlFor={statusId} className="muted small">
            Status
          </label>
          <select
            id={statusId}
            value={detail.status}
            disabled={!canEdit || update.isPending}
            onChange={(event) => {
              update.mutate({ status: event.target.value as CaseStatus });
            }}
          >
            {CASE_STATUSES.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
        <div className="inline-field">
          <label htmlFor={severityId} className="muted small">
            Severity
          </label>
          <select
            id={severityId}
            value={detail.severity}
            disabled={!canEdit || update.isPending}
            onChange={(event) => {
              update.mutate({ severity: event.target.value as Severity });
            }}
          >
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <AssigneeSelect
          label="Assignee"
          value={detail.assignee?.id ?? null}
          disabled={!canEdit || update.isPending}
          onChange={(assigneeId) => {
            update.mutate({ assignee_id: assigneeId });
          }}
        />
      </div>
      <dl className="facts">
        <div>
          <dt>Opened</dt>
          <dd className="mono">{formatUtc(detail.created_at)}</dd>
        </div>
        <div>
          <dt>Resolved</dt>
          <dd className="mono">{detail.resolved_at ? formatUtc(detail.resolved_at) : '—'}</dd>
        </div>
        <div>
          <dt>Closed</dt>
          <dd className="mono">{detail.closed_at ? formatUtc(detail.closed_at) : '—'}</dd>
        </div>
      </dl>
      <form className="form" onSubmit={saveResolution}>
        <div className="field">
          <label htmlFor={resolutionId}>Resolution</label>
          <textarea
            id={resolutionId}
            className="code-input"
            rows={3}
            maxLength={20000}
            placeholder={canEdit ? 'What happened and what was done about it' : undefined}
            readOnly={!canEdit}
            value={resolution}
            onChange={(event) => {
              setResolution(event.target.value);
            }}
          />
        </div>
        {canEdit ? (
          <div>
            <button
              type="submit"
              className="button button--small button--secondary"
              disabled={update.isPending || resolution.trim() === (detail.resolution ?? '')}
            >
              Save resolution
            </button>
          </div>
        ) : null}
      </form>
      {update.isError ? (
        <p className="text-error small" role="alert">
          {update.error.message}
        </p>
      ) : null}
      <div className="inline-field">
        <span className="muted small">Report</span>
        <a
          className="button button--small button--secondary"
          href={caseReportUrl(detail.id, 'markdown')}
          download
        >
          Markdown
        </a>
        <a
          className="button button--small button--secondary"
          href={caseReportUrl(detail.id, 'pdf')}
          download
        >
          PDF
        </a>
      </div>
    </Card>
  );
}

function CaseAlerts({ detail }: { detail: CaseDetail }) {
  const unlink = useUnlinkAlert(detail.id);
  const { canEdit } = usePermissions();
  return (
    <Card title={`Alerts (${String(detail.alerts.length)})`}>
      {detail.alerts.length === 0 ? (
        <p className="muted small">
          No alerts yet. Add them from the <Link to="/alerts">alert queue</Link>.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th scope="col">Alert</th>
                <th scope="col">Severity</th>
                <th scope="col">Status</th>
                <th scope="col">Last seen</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {detail.alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>
                    <Link className="link" to={`/alerts/${String(alert.id)}`}>
                      {alert.title}
                    </Link>
                  </td>
                  <td>
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td>
                    <AlertStatusBadge status={alert.status} />
                  </td>
                  <td className="mono nowrap small">{formatUtc(alert.last_seen)}</td>
                  <td>
                    {canEdit ? (
                      <button
                        type="button"
                        className="link small"
                        aria-label={`Remove alert ${String(alert.id)} from the case`}
                        disabled={unlink.isPending}
                        onClick={() => {
                          unlink.mutate(alert.id);
                        }}
                      >
                        Remove
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function CaseEvidenceList({ detail }: { detail: CaseDetail }) {
  const unpin = useUnpinEvidence(detail.id);
  const { canEdit } = usePermissions();
  return (
    <Card title={`Evidence (${String(detail.evidence.length)})`}>
      {detail.evidence.length === 0 ? (
        <p className="muted small">
          No evidence pinned. Expand an event in the <Link to="/events">event search</Link> or an
          alert timeline to pin it here.
        </p>
      ) : (
        <ul className="evidence-list">
          {detail.evidence.map((item) => (
            <li key={item.id}>
              <div className="evidence-list__head">
                <span className="mono small">{formatUtc(item.event.timestamp)}</span>
                <span className="badge">{item.event.log_source}</span>
                <EntityLink kind="host" value={item.event.host_name} />
                <EntityLink kind="user" value={item.event.user_name} />
                <EntityLink kind="ip" value={item.event.source_ip} />
                {canEdit ? (
                  <button
                    type="button"
                    className="link small"
                    aria-label={`Unpin event ${String(item.event.id)}`}
                    disabled={unpin.isPending}
                    onClick={() => {
                      unpin.mutate(item.id);
                    }}
                  >
                    Unpin
                  </button>
                ) : null}
              </div>
              {item.note ? <p className="small">{item.note}</p> : null}
              <pre className="code code--inline">
                {eventSummary(item.event) || item.event.event_action}
              </pre>
              <span className="muted small">
                Pinned by {item.added_by ?? 'someone'} {formatUtc(item.created_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function CaseNotes({ detail }: { detail: CaseDetail }) {
  const addNote = useAddNote(detail.id);
  const { canEdit } = usePermissions();
  const [body, setBody] = useState('');
  const noteId = useId();

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!body.trim()) return;
    addNote.mutate(body.trim(), {
      onSuccess: () => {
        setBody('');
      },
    });
  }

  return (
    <Card title={`Notes (${String(detail.notes.length)})`}>
      <ol className="notes">
        {detail.notes.map((note) => (
          <li key={note.id}>
            <span className="muted small">
              {note.author ?? 'Someone'} · {formatUtc(note.created_at)}
            </span>
            <p className="note-body">{note.body}</p>
          </li>
        ))}
      </ol>
      {canEdit ? (
        <form className="form" onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor={noteId}>Add a note</label>
            <textarea
              id={noteId}
              className="code-input"
              rows={3}
              maxLength={20000}
              value={body}
              onChange={(event) => {
                setBody(event.target.value);
              }}
            />
          </div>
          <div>
            <button
              type="submit"
              className="button button--small"
              disabled={!body.trim() || addNote.isPending}
            >
              Add note
            </button>
          </div>
          {addNote.isError ? (
            <p className="text-error small" role="alert">
              {addNote.error.message}
            </p>
          ) : null}
        </form>
      ) : null}
    </Card>
  );
}

export function CasePage() {
  const { caseId } = useParams();
  const id = Number(caseId);
  const valid = Number.isInteger(id) && id > 0;
  const detail = useCase(id, valid);

  if (!valid) return <NotFoundPage />;
  if (detail.isPending) return <p className="muted">Loading case…</p>;
  if (detail.isError) {
    return (
      <>
        <PageHeader title={`Case #${String(id)}`} />
        <p className="text-error">Could not load this case.</p>
      </>
    );
  }
  const data = detail.data;

  return (
    <>
      <nav className="breadcrumb small" aria-label="Breadcrumb">
        <Link className="link" to="/cases">
          Cases
        </Link>{' '}
        / #{data.id}
      </nav>
      <PageHeader title={data.title} description={data.description || undefined} />
      <div className="inline-field page-badges">
        <SeverityBadge severity={data.severity} />
        <CaseStatusBadge status={data.status} />
        {data.techniques.map((technique) => (
          <Link key={technique} className="badge" to={`/alerts?technique=${technique}`}>
            {technique}
          </Link>
        ))}
      </div>
      <div className="grid grid--wide">
        <div className="stack stack--flush">
          <CaseAlerts detail={data} />
          <CaseEvidenceList detail={data} />
          <CaseNotes detail={data} />
        </div>
        <div className="stack stack--flush">
          <CaseControls key={data.updated_at} detail={data} />
          <Card title="Entities">
            <dl className="facts">
              {(
                [
                  ['Hosts', 'host', data.entities.hosts],
                  ['IP addresses', 'ip', data.entities.ips],
                  ['Users', 'user', data.entities.users],
                ] as const
              ).map(([label, kind, values]) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd className="tag-list">
                    {values.length
                      ? values.map((value) => <EntityLink key={value} kind={kind} value={value} />)
                      : '—'}
                  </dd>
                </div>
              ))}
            </dl>
          </Card>
          <Card title="Activity">
            <ActivityList entries={data.activity} />
          </Card>
        </div>
      </div>
    </>
  );
}
