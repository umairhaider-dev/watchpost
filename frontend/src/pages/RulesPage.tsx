import { useMemo, useState } from 'react';
import { Link } from 'react-router';

import { usePermissions } from '../api/auth';
import { useRules, useToggleRule } from '../api/queries';
import type { RuleSummary, Severity } from '../api/types';
import { Card } from '../components/Card';
import { DetectionRunsCard } from '../components/detection/DetectionRunsCard';
import { PageHeader } from '../components/PageHeader';
import { SeverityBadge } from '../components/SeverityBadge';
import { Switch } from '../components/Switch';
import { formatUtc } from '../lib/format';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

const TYPE_LABELS: Record<RuleSummary['rule_type'], string> = {
  match: 'Match',
  threshold: 'Threshold',
  sequence: 'Sequence',
  new_value: 'New value',
};

export function RulesPage() {
  const rules = useRules();
  const toggle = useToggleRule();
  const { isAdmin } = usePermissions();
  const [query, setQuery] = useState('');

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (rules.data ?? [])
      .filter(
        (rule) =>
          !needle ||
          rule.title.toLowerCase().includes(needle) ||
          rule.id.includes(needle) ||
          rule.techniques.some((technique) => technique.id.toLowerCase().includes(needle)),
      )
      .sort(
        (a, b) =>
          SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.title.localeCompare(b.title),
      );
  }, [rules.data, query]);

  const enabledCount = rules.data?.filter((rule) => rule.enabled).length ?? 0;

  return (
    <>
      <PageHeader
        title="Detection rules"
        description="Sigma-style rules mapped to MITRE ATT&CK. Open a rule to read how it works, edit it or try it against sample logs."
      />
      <div className="stack stack--flush">
        <DetectionRunsCard />
        <Card
          title="Rules"
          aside={
            rules.data ? (
              <span className="muted">
                {enabledCount} of {rules.data.length} enabled
              </span>
            ) : null
          }
        >
          <input
            type="search"
            className="search"
            placeholder="Filter by title, id or technique (e.g. T1110)"
            aria-label="Filter rules"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
            }}
          />
          {rules.isPending ? <p className="muted">Loading rules…</p> : null}
          {rules.isError ? <p className="text-error">Could not load rules.</p> : null}
          {toggle.isError ? (
            <p className="text-error" role="alert">
              {toggle.error.message}
            </p>
          ) : null}
          {rules.data ? (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">On</th>
                    <th scope="col">Rule</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Type</th>
                    <th scope="col">ATT&amp;CK</th>
                    <th scope="col" className="numeric">
                      Open alerts
                    </th>
                    <th scope="col">Last alert</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((rule) => (
                    <tr key={rule.id} className={rule.enabled ? undefined : 'is-muted'}>
                      <td>
                        <Switch
                          checked={rule.enabled}
                          label={`${rule.enabled ? 'Disable' : 'Enable'} ${rule.title}`}
                          disabled={!isAdmin || toggle.isPending}
                          onChange={(enabled) => {
                            toggle.mutate({ id: rule.id, enabled });
                          }}
                        />
                      </td>
                      <td>
                        <Link className="link" to={`/rules/${rule.id}`}>
                          {rule.title}
                        </Link>
                        <span className="muted small origin">
                          {rule.id}
                          {rule.origin === 'custom' ? ' · custom' : null}
                          {rule.modified ? ' · edited' : null}
                        </span>
                      </td>
                      <td>
                        <SeverityBadge severity={rule.severity} />
                      </td>
                      <td>{TYPE_LABELS[rule.rule_type]}</td>
                      <td>
                        <span className="tag-list">
                          {rule.techniques.map((technique) => (
                            <span
                              key={technique.id}
                              className="badge"
                              title={technique.name ?? undefined}
                            >
                              {technique.id}
                            </span>
                          ))}
                        </span>
                      </td>
                      <td className="numeric">{rule.open_alerts}</td>
                      <td className="nowrap small">
                        {rule.last_alert_at ? formatUtc(rule.last_alert_at) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          {rules.data && visible.length === 0 ? (
            <p className="muted">No rule matches “{query}”.</p>
          ) : null}
        </Card>
      </div>
    </>
  );
}
