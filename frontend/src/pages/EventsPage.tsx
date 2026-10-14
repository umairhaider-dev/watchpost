import { type SubmitEvent, useId, useState } from 'react';
import { useSearchParams } from 'react-router';

import { useEventSearch } from '../api/queries';
import type { LogSource } from '../api/types';
import { Card } from '../components/Card';
import { EventTable } from '../components/events/EventTable';
import { PageHeader } from '../components/PageHeader';
import { TimeRangeSelect } from '../components/TimeRangeSelect';
import { isTimeRange, type TimeRange } from '../lib/time';

const SOURCES: { value: LogSource | ''; label: string }[] = [
  { value: '', label: 'All sources' },
  { value: 'linux_auth', label: 'Linux auth' },
  { value: 'web_access', label: 'Web access' },
  { value: 'windows_security', label: 'Windows Security' },
  { value: 'sysmon', label: 'Sysmon' },
  { value: 'json', label: 'JSON' },
];

const EXAMPLES = [
  'user.name:root AND event.outcome:failure',
  'source.ip:203.0.113.0/24 OR host:"web-01"',
  'status:>=500 -url:*healthz*',
  '"Failed password"',
];

function QueryHelp() {
  return (
    <details className="query-help">
      <summary className="small">Query syntax</summary>
      <ul className="plain-list bullets small">
        <li>
          <code>field:value</code> matches a field; a word or <code>&quot;phrase&quot;</code> on its
          own searches the message, command line and URL.
        </li>
        <li>
          Combine with <code>AND</code> (or a space), <code>OR</code>, <code>NOT</code> or a leading{' '}
          <code>-</code>, and group with parentheses.
        </li>
        <li>
          <code>*</code> and <code>?</code> are wildcards; <code>field:*</code> means the field is
          present. Keyword fields such as <code>user.name</code> match exactly.
        </li>
        <li>
          Compare numbers and times with <code>&gt;</code>, <code>&gt;=</code>, <code>&lt;</code>{' '}
          and <code>&lt;=</code>; IP fields take CIDR ranges.
        </li>
        <li>
          Shortcuts: <code>host</code>, <code>user</code>, <code>ip</code> (either end),{' '}
          <code>action</code>, <code>url</code>, <code>status</code>; <code>raw.path</code> reaches
          into the original record. Field names are listed on the Event schema page.
        </li>
      </ul>
      <p className="small muted">Examples:</p>
      <ul className="plain-list small">
        {EXAMPLES.map((example) => (
          <li key={example}>
            <code>{example}</code>
          </li>
        ))}
      </ul>
    </details>
  );
}

/** The query box; keyed by the applied query so links to a new search reset it. */
function SearchForm({ initial, onSearch }: { initial: string; onSearch: (q: string) => void }) {
  const [draft, setDraft] = useState(initial);
  const queryId = useId();

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    onSearch(draft.trim());
  }

  return (
    <form className="search-form" onSubmit={handleSubmit}>
      <label htmlFor={queryId} className="visually-hidden">
        Query
      </label>
      <input
        id={queryId}
        type="search"
        className="search grow mono"
        placeholder="e.g. user.name:root AND event.outcome:failure"
        maxLength={2000}
        value={draft}
        onChange={(event) => {
          setDraft(event.target.value);
        }}
      />
      <button type="submit" className="button">
        Search
      </button>
    </form>
  );
}

export function EventsPage() {
  const [params, setParams] = useSearchParams();
  const q = params.get('q') ?? '';
  const rangeParam = params.get('range');
  const range: TimeRange = isTimeRange(rangeParam) ? rangeParam : 'all';
  const [source, setSource] = useState<LogSource | ''>('');
  const [iocOnly, setIocOnly] = useState(false);
  const events = useEventSearch({ q, range, logSource: source, iocOnly });
  const sourceId = useId();
  const items = events.data?.pages.flatMap((page) => page.items) ?? [];

  function update(next: { q?: string; range?: TimeRange }) {
    const merged = new URLSearchParams(params);
    for (const [key, value] of Object.entries(next)) {
      if (value && !(key === 'range' && value === 'all')) merged.set(key, value);
      else merged.delete(key);
    }
    setParams(merged);
  }

  return (
    <>
      <PageHeader
        title="Event search"
        description="Search every stored event with a field:value query and a time range. Newest events come first."
      />
      <Card title="Search">
        <SearchForm
          key={q}
          initial={q}
          onSearch={(next) => {
            update({ q: next });
          }}
        />
        <div className="filter-bar">
          <TimeRangeSelect
            value={range}
            onChange={(next) => {
              update({ range: next });
            }}
          />
          <div className="inline-field">
            <label htmlFor={sourceId} className="muted small">
              Source
            </label>
            <select
              id={sourceId}
              value={source}
              onChange={(event) => {
                setSource(event.target.value as LogSource | '');
              }}
            >
              {SOURCES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          <button
            type="button"
            className="chip"
            aria-pressed={iocOnly}
            onClick={() => {
              setIocOnly((current) => !current);
            }}
          >
            Threat intel matches
          </button>
        </div>
        <QueryHelp />
      </Card>
      <div className="stack">
        <Card
          title="Results"
          aside={
            events.data ? (
              <span className="muted">
                {items.length}
                {events.hasNextPage ? '+' : ''} events
              </span>
            ) : null
          }
        >
          {events.isPending ? <p className="muted">Searching…</p> : null}
          {events.isError ? (
            <p className="text-error" role="alert">
              {events.error.message}
            </p>
          ) : null}
          {events.isSuccess && items.length === 0 ? (
            <p className="muted">
              {q || iocOnly || source || range !== 'all'
                ? 'No events match this search.'
                : 'No events yet. Ingest a log file to see it here.'}
            </p>
          ) : null}
          {items.length > 0 ? <EventTable events={items} /> : null}
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
      </div>
    </>
  );
}
