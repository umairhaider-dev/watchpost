import { useId, useState } from 'react';

import { useIngestInfo, useTestRule } from '../../api/queries';
import type { RuleTestResult } from '../../api/types';
import { countOf, formatUtc } from '../../lib/format';
import { Card } from '../Card';

/** Matches the API's limit on pasted samples. */
const MAX_SAMPLE_CHARS = 1_000_000;

function TestResults({ result }: { result: RuleTestResult }) {
  return (
    <div className="test-results" aria-live="polite">
      <p>
        Parsed <strong>{result.events_parsed}</strong> events with <code>{result.parser}</code>
        {result.malformed_count > 0
          ? `, ${String(result.malformed_count)} lines could not be parsed`
          : null}
        {result.truncated ? ' (sample cut short)' : null}.{' '}
        {result.hits.length === 0 ? (
          <strong>The rule did not fire.</strong>
        ) : (
          <strong className="text-warn">
            The rule fired{' '}
            {result.hits.length === 1 ? 'once' : `${String(result.hits.length)} times`}.
          </strong>
        )}
      </p>
      {result.hits.map((hit) => (
        <div key={hit.title + hit.first_seen} className="hit">
          <div className="hit__title">{hit.title}</div>
          <div className="muted small">
            {countOf(hit.event_count, 'event')} · {formatUtc(hit.first_seen)} →{' '}
            {formatUtc(hit.last_seen)} · lines {hit.lines.join(', ')}
          </div>
        </div>
      ))}
      {result.matched_events.length > 0 ? (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th scope="col">Line</th>
                <th scope="col">Time</th>
                <th scope="col">Action</th>
                <th scope="col">User</th>
                <th scope="col">Source IP</th>
                <th scope="col">Message</th>
              </tr>
            </thead>
            <tbody>
              {result.matched_events.map((event) => (
                <tr key={event.line}>
                  <td className="mono">{event.line}</td>
                  <td className="mono nowrap">{formatUtc(event.timestamp)}</td>
                  <td>
                    <span className="action" data-outcome={event.event_outcome ?? 'unknown'}>
                      {event.event_action ?? '—'}
                    </span>
                  </td>
                  <td>{event.user_name ?? '—'}</td>
                  <td className="mono">{event.source_ip ?? '—'}</td>
                  <td className="excerpt">{event.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {result.malformed.length > 0 ? (
        <details>
          <summary className="muted small">Lines that could not be parsed</summary>
          <ul className="plain-list small">
            {result.malformed.map((line) => (
              <li key={line.line}>
                <span className="mono">{line.line}</span>: {line.reason}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

/** Try the editor's current YAML against pasted log lines; nothing is stored. */
export function RuleTestPanel({ sourceYaml }: { sourceYaml: string }) {
  const info = useIngestInfo();
  const test = useTestRule();
  const [sample, setSample] = useState('');
  const [parser, setParser] = useState('auto');
  const sampleId = useId();
  const parserId = useId();

  return (
    <Card title="Test against sample logs">
      <div className="field">
        <label htmlFor={sampleId}>Sample logs</label>
        <textarea
          id={sampleId}
          className="code-input"
          rows={10}
          spellCheck={false}
          maxLength={MAX_SAMPLE_CHARS}
          placeholder="Paste log lines here (auth.log, access log lines or JSON records)"
          value={sample}
          onChange={(event) => {
            setSample(event.target.value);
          }}
        />
      </div>
      <div className="inline-field">
        <label htmlFor={parserId} className="muted small">
          Format
        </label>
        <select
          id={parserId}
          value={parser}
          onChange={(event) => {
            setParser(event.target.value);
          }}
        >
          <option value="auto">Detect automatically</option>
          {info.data?.parsers.map((candidate) => (
            <option key={candidate.name} value={candidate.name}>
              {candidate.label}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="button"
          disabled={!sample.trim() || test.isPending}
          onClick={() => {
            test.mutate({ sourceYaml, sample, parser });
          }}
        >
          {test.isPending ? 'Testing…' : 'Run test'}
        </button>
      </div>
      {test.isError ? (
        <p className="text-error" role="alert">
          {test.error.message}
        </p>
      ) : null}
      {test.data ? <TestResults result={test.data} /> : null}
    </Card>
  );
}
