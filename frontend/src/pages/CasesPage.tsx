import { type SubmitEvent, useId, useState } from 'react';
import { Link, useNavigate } from 'react-router';

import {
  type CaseFilters,
  useAssignableUsers,
  useCases,
  useCreateCase,
} from '../api/investigation';
import type { Severity } from '../api/types';
import { Card } from '../components/Card';
import { PageHeader } from '../components/PageHeader';
import { SeverityBadge } from '../components/SeverityBadge';
import { CaseStatusBadge } from '../components/StatusBadges';
import { countOf, formatNumber, formatUtc } from '../lib/format';
import { CASE_STATUSES } from '../lib/labels';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];

function NewCaseForm() {
  const create = useCreateCase();
  const navigate = useNavigate();
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<Severity>('medium');
  const [description, setDescription] = useState('');
  const titleId = useId();
  const severityId = useId();
  const descriptionId = useId();

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!title.trim()) return;
    create.mutate(
      { title: title.trim(), severity, description: description.trim() },
      {
        onSuccess: (detail) => {
          void navigate(`/cases/${String(detail.id)}`);
        },
      },
    );
  }

  return (
    <Card title="Open a case">
      <form className="form" onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor={titleId}>Title</label>
          <input
            id={titleId}
            type="text"
            maxLength={255}
            placeholder="e.g. Credential theft on ws-fin-07"
            value={title}
            onChange={(event) => {
              setTitle(event.target.value);
            }}
          />
        </div>
        <div className="field">
          <label htmlFor={severityId}>Severity</label>
          <select
            id={severityId}
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value as Severity);
            }}
          >
            {SEVERITIES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor={descriptionId}>Description</label>
          <textarea
            id={descriptionId}
            className="code-input"
            rows={4}
            maxLength={20000}
            value={description}
            onChange={(event) => {
              setDescription(event.target.value);
            }}
          />
        </div>
        <div>
          <button type="submit" className="button" disabled={!title.trim() || create.isPending}>
            Open case
          </button>
        </div>
        {create.isError ? (
          <p className="text-error small" role="alert">
            {create.error.message}
          </p>
        ) : null}
        <p className="muted small">
          To open a case around alerts, select them in the alert queue instead.
        </p>
      </form>
    </Card>
  );
}

export function CasesPage() {
  const [filters, setFilters] = useState<CaseFilters>({ status: 'active', assignee: '', q: '' });
  const cases = useCases(filters);
  const users = useAssignableUsers();
  const statusId = useId();
  const assigneeId = useId();
  const names = new Map(users.data?.map((user) => [user.id, user.username]));
  const items = cases.data?.items ?? [];

  return (
    <>
      <PageHeader
        title="Cases"
        description="Investigations that group related alerts, with notes, pinned evidence and a full activity history."
      />
      <div className="grid grid--wide">
        <Card
          title="Cases"
          aside={
            cases.data ? <span className="muted">{formatNumber(cases.data.total)}</span> : null
          }
        >
          <div className="filter-bar">
            <input
              type="search"
              className="search grow"
              aria-label="Search case titles"
              placeholder="Search titles"
              value={filters.q}
              onChange={(event) => {
                setFilters((current) => ({ ...current, q: event.target.value }));
              }}
            />
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
                    status: event.target.value as CaseFilters['status'],
                  }));
                }}
              >
                <option value="active">Open or in progress</option>
                <option value="">Any status</option>
                {CASE_STATUSES.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="inline-field">
              <label htmlFor={assigneeId} className="muted small">
                Assignee
              </label>
              <select
                id={assigneeId}
                value={filters.assignee}
                onChange={(event) => {
                  setFilters((current) => ({ ...current, assignee: event.target.value }));
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
          </div>
          {cases.isPending ? <p className="muted">Loading cases…</p> : null}
          {cases.isError ? <p className="text-error">Could not load cases.</p> : null}
          {cases.isSuccess && items.length === 0 ? (
            <p className="muted">No cases match these filters.</p>
          ) : null}
          {items.length > 0 ? (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Case</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Status</th>
                    <th scope="col">Assignee</th>
                    <th scope="col" className="numeric">
                      Alerts
                    </th>
                    <th scope="col">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <Link className="link" to={`/cases/${String(item.id)}`}>
                          {item.title}
                        </Link>
                        <span className="muted small origin">
                          #{item.id} · {countOf(item.note_count, 'note')} ·{' '}
                          {countOf(item.evidence_count, 'evidence item')}
                        </span>
                      </td>
                      <td>
                        <SeverityBadge severity={item.severity} />
                      </td>
                      <td>
                        <CaseStatusBadge status={item.status} />
                      </td>
                      <td className="small">
                        {item.assignee_id !== null
                          ? (names.get(item.assignee_id) ?? `#${String(item.assignee_id)}`)
                          : '—'}
                      </td>
                      <td className="numeric">
                        {item.open_alert_count}/{item.alert_count}
                      </td>
                      <td className="mono nowrap small">{formatUtc(item.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </Card>
        <NewCaseForm />
      </div>
    </>
  );
}
