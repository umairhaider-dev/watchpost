import { type SubmitEvent, useId, useState } from 'react';
import { Link } from 'react-router';

import { AUDIT_PAGE_SIZE, type AuditFilters, useAuditLog } from '../api/admin';
import type { AuditEntry } from '../api/types';
import { Card } from '../components/Card';
import { PageHeader } from '../components/PageHeader';
import { formatNumber, formatUtc } from '../lib/format';
import { AUDIT_AREAS, auditActionLabel, formatAuditDetails, isRefusal } from '../lib/labels';

const TARGET_PAGES: Record<string, string> = { alert: 'alerts', case: 'cases', rule: 'rules' };

function Target({ entry }: { entry: AuditEntry }) {
  if (!entry.target_type) return <>—</>;
  const label = `${entry.target_type.replaceAll('_', ' ')} ${entry.target_id ?? ''}`.trim();
  const page = TARGET_PAGES[entry.target_type];
  if (page && entry.target_id) {
    return (
      <Link className="link" to={`/${page}/${encodeURIComponent(entry.target_id)}`}>
        {label}
      </Link>
    );
  }
  return <>{label}</>;
}

function Pager({
  offset,
  total,
  onMove,
}: {
  offset: number;
  total: number;
  onMove: (offset: number) => void;
}) {
  const last = Math.min(offset + AUDIT_PAGE_SIZE, total);
  return (
    <div className="inline-field">
      <span className="muted small">
        {formatNumber(offset + 1)}–{formatNumber(last)} of {formatNumber(total)}
      </span>
      <button
        type="button"
        className="button button--secondary button--small"
        disabled={offset === 0}
        onClick={() => {
          onMove(Math.max(0, offset - AUDIT_PAGE_SIZE));
        }}
      >
        Newer
      </button>
      <button
        type="button"
        className="button button--secondary button--small"
        disabled={last >= total}
        onClick={() => {
          onMove(offset + AUDIT_PAGE_SIZE);
        }}
      >
        Older
      </button>
    </div>
  );
}

export function AuditPage() {
  const [filters, setFilters] = useState<AuditFilters>({ action: '', username: '', offset: 0 });
  const [username, setUsername] = useState('');
  const log = useAuditLog(filters);
  const areaId = useId();
  const userId = useId();
  const items = log.data?.items ?? [];

  function applyUsername(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilters((current) => ({ ...current, username: username.trim(), offset: 0 }));
  }

  function showUser(name: string) {
    setUsername(name);
    setFilters((current) => ({ ...current, username: name, offset: 0 }));
  }

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Who did what and when: sign-ins and failed attempts, triage and case work, rule edits, uploads, intel changes and account management. Entries cannot be edited or deleted from the app."
      />
      <Card
        title="Entries"
        aside={log.data ? <span className="muted">{formatNumber(log.data.total)}</span> : null}
      >
        <form className="filter-bar" onSubmit={applyUsername}>
          <div className="inline-field">
            <label htmlFor={areaId} className="muted small">
              Area
            </label>
            <select
              id={areaId}
              value={filters.action}
              onChange={(event) => {
                setFilters((current) => ({ ...current, action: event.target.value, offset: 0 }));
              }}
            >
              <option value="">Everything</option>
              {AUDIT_AREAS.map((area) => (
                <option key={area.value} value={area.value}>
                  {area.label}
                </option>
              ))}
            </select>
          </div>
          <div className="inline-field">
            <label htmlFor={userId} className="muted small">
              User
            </label>
            <input
              id={userId}
              type="text"
              spellCheck={false}
              maxLength={64}
              placeholder="Exact user name"
              value={username}
              onChange={(event) => {
                setUsername(event.target.value);
              }}
            />
            <button type="submit" className="button button--secondary button--small">
              Filter
            </button>
            {filters.username ? (
              <button
                type="button"
                className="link small"
                onClick={() => {
                  showUser('');
                }}
              >
                Clear
              </button>
            ) : null}
          </div>
          {log.data && log.data.total > 0 ? (
            <div className="grow-right">
              <Pager
                offset={filters.offset}
                total={log.data.total}
                onMove={(offset) => {
                  setFilters((current) => ({ ...current, offset }));
                }}
              />
            </div>
          ) : null}
        </form>
        {log.isPending ? <p className="muted">Loading the audit log…</p> : null}
        {log.isError ? <p className="text-error">Could not load the audit log.</p> : null}
        {log.isSuccess && items.length === 0 ? (
          <p className="muted">No entries match these filters.</p>
        ) : null}
        {items.length > 0 ? (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">User</th>
                  <th scope="col">Action</th>
                  <th scope="col">Target</th>
                  <th scope="col">Details</th>
                  <th scope="col">Address</th>
                </tr>
              </thead>
              <tbody>
                {items.map((entry) => (
                  <tr key={entry.id}>
                    <td className="mono nowrap small">{formatUtc(entry.occurred_at)}</td>
                    <td className="nowrap">
                      {entry.username ? (
                        <button
                          type="button"
                          className="link mono small"
                          title={`Show only ${entry.username}`}
                          onClick={() => {
                            showUser(entry.username ?? '');
                          }}
                        >
                          {entry.username}
                        </button>
                      ) : (
                        <span className="muted">system</span>
                      )}
                    </td>
                    <td>
                      <span
                        className={isRefusal(entry.action) ? 'text-error' : undefined}
                        title={entry.action}
                      >
                        {auditActionLabel(entry.action)}
                      </span>
                    </td>
                    <td className="small nowrap">
                      <Target entry={entry} />
                    </td>
                    <td className="small audit-details">{formatAuditDetails(entry.details)}</td>
                    <td className="mono small nowrap" title={entry.user_agent ?? undefined}>
                      {entry.ip_address ?? '—'}
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
