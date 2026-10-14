import { Fragment, useId, useState } from 'react';

import { type IocFilters, useDeleteIoc, useIoc, useIocs, useUpdateIoc } from '../../api/queries';
import type { Ioc, IocType } from '../../api/types';
import { formatNumber, formatUtc } from '../../lib/format';
import { IOC_TYPE_LABELS } from '../../lib/intel';
import { Card } from '../Card';
import { Switch } from '../Switch';

const TYPES = Object.entries(IOC_TYPE_LABELS) as [IocType, string][];
const COLUMN_COUNT = 7;

function IocMatches({ ioc }: { ioc: Ioc }) {
  const detail = useIoc(ioc.id);

  return (
    <div className="event-details">
      <dl className="facts facts--inline">
        <div>
          <dt>Added</dt>
          <dd className="mono">{formatUtc(ioc.created_at)}</dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd className="mono">{ioc.expires_at ? formatUtc(ioc.expires_at) : 'never'}</dd>
        </div>
        <div>
          <dt>Last matched</dt>
          <dd className="mono">{ioc.last_matched_at ? formatUtc(ioc.last_matched_at) : '—'}</dd>
        </div>
      </dl>
      {ioc.tags.length > 0 ? (
        <span className="tag-list">
          {ioc.tags.map((tag) => (
            <span key={tag} className="badge">
              {tag}
            </span>
          ))}
        </span>
      ) : null}
      <h3 className="subheading">Matching events</h3>
      {detail.isPending ? <p className="muted small">Loading matches…</p> : null}
      {detail.isError ? <p className="text-error small">Could not load matches.</p> : null}
      {detail.data?.matches.length === 0 ? (
        <p className="muted small">No stored event has matched this indicator.</p>
      ) : null}
      {detail.data && detail.data.matches.length > 0 ? (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Source</th>
                <th scope="col">Host</th>
                <th scope="col">Matched in</th>
                <th scope="col">Details</th>
              </tr>
            </thead>
            <tbody>
              {detail.data.matches.map((match) => (
                <tr key={`${String(match.event_id)}:${match.field}`}>
                  <td className="mono nowrap">{formatUtc(match.timestamp)}</td>
                  <td>
                    <span className="badge">{match.log_source}</span>
                  </td>
                  <td>{match.host_name ?? '—'}</td>
                  <td className="mono">{match.field}</td>
                  <td className="excerpt">{match.message ?? match.event_action ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

export function IocTable() {
  const [filters, setFilters] = useState<IocFilters>({ q: '', iocType: '', matchedOnly: false });
  const [expanded, setExpanded] = useState<number | null>(null);
  const iocs = useIocs(filters);
  const update = useUpdateIoc();
  const remove = useDeleteIoc();
  const typeId = useId();
  const items = iocs.data?.items ?? [];
  const mutationError = update.error ?? remove.error;

  function confirmDelete(ioc: Ioc) {
    const message = `Delete ${ioc.value}? Events it matched will no longer be flagged by it.`;
    if (window.confirm(message)) remove.mutate(ioc.id);
  }

  return (
    <Card
      title="Indicators"
      aside={iocs.data ? <span className="muted">{formatNumber(iocs.data.total)}</span> : null}
    >
      <div className="filter-bar">
        <input
          type="search"
          className="search grow"
          placeholder="Search values and descriptions"
          aria-label="Search indicators"
          value={filters.q}
          onChange={(event) => {
            setFilters((current) => ({ ...current, q: event.target.value }));
          }}
        />
        <div className="inline-field">
          <label htmlFor={typeId} className="muted small">
            Type
          </label>
          <select
            id={typeId}
            value={filters.iocType}
            onChange={(event) => {
              setFilters((current) => ({
                ...current,
                iocType: event.target.value as IocType | '',
              }));
            }}
          >
            <option value="">Any type</option>
            {TYPES.map(([type, label]) => (
              <option key={type} value={type}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <button
          type="button"
          className="chip"
          aria-pressed={filters.matchedOnly}
          onClick={() => {
            setFilters((current) => ({ ...current, matchedOnly: !current.matchedOnly }));
          }}
        >
          Seen in events
        </button>
      </div>
      {mutationError ? (
        <p className="text-error small" role="alert">
          {mutationError.message}
        </p>
      ) : null}
      {iocs.isPending ? <p className="muted">Loading indicators…</p> : null}
      {iocs.isError ? <p className="text-error">Could not load indicators.</p> : null}
      {iocs.isSuccess && items.length === 0 ? (
        <p className="muted">No indicators match. Import a feed or add one to get started.</p>
      ) : null}
      {items.length > 0 ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">On</th>
                <th scope="col">Indicator</th>
                <th scope="col">Type</th>
                <th scope="col">Source</th>
                <th scope="col" className="numeric">
                  Confidence
                </th>
                <th scope="col" className="numeric">
                  Matches
                </th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((ioc) => {
                const isOpen = expanded === ioc.id;
                return (
                  <Fragment key={ioc.id}>
                    <tr
                      className={[isOpen ? 'is-open' : '', ioc.is_active ? '' : 'is-muted']
                        .filter(Boolean)
                        .join(' ')}
                    >
                      <td>
                        <Switch
                          checked={ioc.is_active}
                          label={`${ioc.is_active ? 'Deactivate' : 'Activate'} ${ioc.value}`}
                          disabled={update.isPending}
                          onChange={(active) => {
                            update.mutate({ id: ioc.id, is_active: active });
                          }}
                        />
                      </td>
                      <td>
                        <button
                          type="button"
                          className="row-toggle"
                          aria-expanded={isOpen}
                          onClick={() => {
                            setExpanded(isOpen ? null : ioc.id);
                          }}
                        >
                          <span className="row-toggle__chevron" aria-hidden="true" />
                          <span className="mono ioc-value">{ioc.value}</span>
                        </button>
                        {ioc.description ? (
                          <span className="muted small origin">{ioc.description}</span>
                        ) : null}
                      </td>
                      <td>
                        <span className="badge">{IOC_TYPE_LABELS[ioc.ioc_type]}</span>
                      </td>
                      <td className="small">{ioc.source}</td>
                      <td className="numeric">{ioc.confidence ?? '—'}</td>
                      <td className="numeric">
                        {ioc.match_count > 0 ? (
                          <span className="text-warn">{formatNumber(ioc.match_count)}</span>
                        ) : (
                          '0'
                        )}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="link small"
                          aria-label={`Delete ${ioc.value}`}
                          disabled={remove.isPending}
                          onClick={() => {
                            confirmDelete(ioc);
                          }}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                    {isOpen ? (
                      <tr className="row-details">
                        <td colSpan={COLUMN_COUNT}>
                          <IocMatches ioc={ioc} />
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
  );
}
