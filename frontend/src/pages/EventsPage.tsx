import { Fragment, useId, useState } from 'react';

import { useEventIndicators, useEvents } from '../api/queries';
import type { EventRecord, LogSource } from '../api/types';
import { Card } from '../components/Card';
import { PageHeader } from '../components/PageHeader';
import { formatUtc } from '../lib/format';
import { IOC_TYPE_LABELS } from '../lib/intel';

const SOURCES: { value: LogSource | ''; label: string }[] = [
  { value: '', label: 'All sources' },
  { value: 'linux_auth', label: 'Linux auth' },
  { value: 'web_access', label: 'Web access' },
  { value: 'windows_security', label: 'Windows Security' },
  { value: 'sysmon', label: 'Sysmon' },
  { value: 'json', label: 'JSON' },
];

const COLUMN_COUNT = 7;

function summary(event: EventRecord): string {
  if (event.process_command_line) return event.process_command_line;
  if (event.url_original) {
    return `${event.http_method ?? ''} ${event.url_original} ${String(event.http_status_code ?? '')}`.trim();
  }
  return event.message ?? '';
}

function EventIndicators({ id }: { id: number }) {
  const indicators = useEventIndicators(id);
  if (indicators.isPending) return <p className="muted small">Loading matched indicators…</p>;
  if (indicators.isError) return <p className="text-error small">Could not load indicators.</p>;
  return (
    <ul className="context-list">
      {indicators.data.map((indicator) => (
        <li key={`${String(indicator.ioc_id)}:${indicator.field}`}>
          <span className="mono indicator__value">{indicator.value}</span>
          <span className="badge">{IOC_TYPE_LABELS[indicator.ioc_type]}</span>
          <span className="muted small">
            in {indicator.field} · {indicator.source}
            {indicator.confidence !== null ? ` · confidence ${String(indicator.confidence)}` : ''}
          </span>
          {indicator.description ? <span className="small">{indicator.description}</span> : null}
        </li>
      ))}
    </ul>
  );
}

function EventDetails({ event }: { event: EventRecord }) {
  const extras: [string, string | number | null][] = [
    ['Event code', event.event_code],
    ['Category', event.event_category],
    ['Process', event.process_name],
    ['Parent process', event.process_parent_name],
    [
      'Destination',
      event.destination_ip
        ? `${event.destination_ip}:${String(event.destination_port ?? '')}`
        : null,
    ],
    ['User agent', event.user_agent],
    ['Ingested', formatUtc(event.ingested_at)],
  ];

  return (
    <div className="event-details">
      {event.ioc_matched ? (
        <>
          <h3 className="subheading">Threat intel matches</h3>
          <EventIndicators id={event.id} />
        </>
      ) : null}
      <dl className="facts facts--inline">
        {extras
          .filter(
            (entry): entry is [string, string | number] => entry[1] !== null && entry[1] !== '',
          )
          .map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd className="mono">{value}</dd>
            </div>
          ))}
      </dl>
      <h3 className="subheading">Raw event</h3>
      <pre className="code">{JSON.stringify(event.raw_event, null, 2)}</pre>
    </div>
  );
}

export function EventsPage() {
  const [source, setSource] = useState<LogSource | ''>('');
  const [iocOnly, setIocOnly] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const events = useEvents(source, iocOnly);
  const selectId = useId();
  const items = events.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <>
      <PageHeader
        title="Events"
        description="The most recent normalised events, newest first. Expand a row to see the original record."
      />
      <Card
        title="Recent events"
        aside={
          <div className="inline-field">
            <button
              type="button"
              className="chip"
              aria-pressed={iocOnly}
              onClick={() => {
                setIocOnly((current) => !current);
                setExpanded(null);
              }}
            >
              Threat intel matches
            </button>
            <label htmlFor={selectId} className="muted small">
              Source
            </label>
            <select
              id={selectId}
              value={source}
              onChange={(event) => {
                setSource(event.target.value as LogSource | '');
                setExpanded(null);
              }}
            >
              {SOURCES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        }
      >
        {events.isPending ? <p className="muted">Loading events…</p> : null}
        {events.isError ? <p className="text-error">Could not load events.</p> : null}
        {events.isSuccess && items.length === 0 ? (
          <p className="muted">
            {iocOnly
              ? 'No events have matched a threat indicator.'
              : 'No events yet. Ingest a log file to see it here.'}
          </p>
        ) : null}
        {items.length > 0 ? (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Source</th>
                  <th scope="col">Host</th>
                  <th scope="col">User</th>
                  <th scope="col">Source IP</th>
                  <th scope="col">Action</th>
                  <th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {items.map((event) => {
                  const isOpen = expanded === event.id;
                  return (
                    <Fragment key={event.id}>
                      <tr className={isOpen ? 'is-open' : undefined}>
                        <td className="nowrap">
                          <button
                            type="button"
                            className="row-toggle"
                            aria-expanded={isOpen}
                            onClick={() => {
                              setExpanded(isOpen ? null : event.id);
                            }}
                          >
                            <span className="row-toggle__chevron" aria-hidden="true" />
                            <span className="mono">{formatUtc(event.timestamp)}</span>
                          </button>
                        </td>
                        <td className="nowrap">
                          <span className="badge">{event.log_source}</span>
                          {event.ioc_matched ? (
                            <span className="ioc-flag" title="Matched a threat indicator">
                              IOC
                            </span>
                          ) : null}
                        </td>
                        <td>{event.host_name ?? '—'}</td>
                        <td>{event.user_name ?? '—'}</td>
                        <td className="mono">{event.source_ip ?? '—'}</td>
                        <td>
                          {event.event_action ? (
                            <span
                              className="action"
                              data-outcome={event.event_outcome ?? 'unknown'}
                            >
                              {event.event_action}
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td className="excerpt">{summary(event)}</td>
                      </tr>
                      {isOpen ? (
                        <tr className="row-details">
                          <td colSpan={COLUMN_COUNT}>
                            <EventDetails event={event} />
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
        {events.hasNextPage ? (
          <div>
            <button
              type="button"
              className="button button--secondary"
              disabled={events.isFetchingNextPage}
              onClick={() => {
                void events.fetchNextPage();
              }}
            >
              {events.isFetchingNextPage ? 'Loading…' : 'Load older events'}
            </button>
          </div>
        ) : null}
      </Card>
    </>
  );
}
