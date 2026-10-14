import { useState } from 'react';
import { Link } from 'react-router';

import { useAttackMatrix } from '../api/investigation';
import type { TechniqueCell } from '../api/types';
import { Card } from '../components/Card';
import { PageHeader } from '../components/PageHeader';
import { TimeRangeSelect } from '../components/TimeRangeSelect';
import { countOf, formatUtc } from '../lib/format';
import type { TimeRange } from '../lib/time';

/** How strongly a cell is highlighted: detected, covered only, or neither. */
function cellState(cell: TechniqueCell): 'detected' | 'covered' | 'uncovered' {
  if (cell.alerts > 0) return 'detected';
  return cell.enabled_rules > 0 ? 'covered' : 'uncovered';
}

function Cell({ cell }: { cell: TechniqueCell }) {
  const state = cellState(cell);
  const description = [
    `${String(cell.enabled_rules)} of ${countOf(cell.rules.length, 'rule')} enabled`,
    `${countOf(cell.alerts, 'alert')} (${String(cell.open_alerts)} open)`,
    cell.last_seen ? `last ${formatUtc(cell.last_seen)}` : null,
  ]
    .filter(Boolean)
    .join(' · ');
  const body = (
    <>
      <span className="matrix__id mono">{cell.id}</span>
      <span className="matrix__name">{cell.name ?? 'Unknown technique'}</span>
      <span className="matrix__meta small">
        {cell.alerts > 0 ? countOf(cell.alerts, 'alert') : countOf(cell.enabled_rules, 'rule')}
      </span>
    </>
  );
  return (
    <li className="matrix__cell" data-state={state} title={description}>
      {cell.alerts > 0 ? (
        <Link to={`/alerts?technique=${cell.id}`} aria-label={`${cell.id}: ${description}`}>
          {body}
        </Link>
      ) : (
        <div aria-label={`${cell.id}: ${description}`}>{body}</div>
      )}
    </li>
  );
}

export function MitrePage() {
  const [range, setRange] = useState<TimeRange>('30d');
  const matrix = useAttackMatrix(range);
  const data = matrix.data;

  return (
    <>
      <PageHeader
        title="MITRE ATT&CK"
        description="Techniques the detection rules cover, by tactic. Highlighted techniques raised alerts in the chosen period; open one to see its alerts."
      />
      <Card
        title="Coverage and detections"
        aside={<TimeRangeSelect label="Alerts from" value={range} onChange={setRange} />}
      >
        {matrix.isPending ? <p className="muted">Loading…</p> : null}
        {matrix.isError ? <p className="text-error">Could not load the matrix.</p> : null}
        {data ? (
          <>
            <dl className="stat-row">
              <div>
                <dt>Techniques covered by enabled rules</dt>
                <dd>{data.techniques_covered}</dd>
              </div>
              <div>
                <dt>Techniques detected</dt>
                <dd>{data.techniques_detected}</dd>
              </div>
              <div>
                <dt>Tactics covered</dt>
                <dd>
                  {data.tactics.filter((tactic) => tactic.techniques.length > 0).length} of{' '}
                  {data.tactics.length}
                </dd>
              </div>
            </dl>
            <ul className="matrix__legend small">
              <li data-state="detected">Detected</li>
              <li data-state="covered">Covered, no alerts</li>
              <li data-state="uncovered">Rules disabled</li>
            </ul>
            <div className="matrix" role="list" aria-label="ATT&CK tactics">
              {data.tactics.map((tactic) => (
                <section
                  key={tactic.id}
                  className="matrix__column"
                  role="listitem"
                  aria-label={tactic.name}
                >
                  <h3 className="matrix__tactic">
                    {tactic.name}
                    <span className="muted small"> {tactic.id}</span>
                  </h3>
                  {tactic.techniques.length ? (
                    <ul className="matrix__cells">
                      {tactic.techniques.map((cell) => (
                        <Cell key={cell.id} cell={cell} />
                      ))}
                    </ul>
                  ) : (
                    <p className="muted small">No rules yet</p>
                  )}
                </section>
              ))}
            </div>
          </>
        ) : null}
      </Card>
    </>
  );
}
