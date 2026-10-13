import { useId, useState } from 'react';
import { Link, useParams } from 'react-router';

import { useRule, useSaveRule, useToggleRule, useValidateRule } from '../api/queries';
import type { RuleDetail } from '../api/types';
import { Card } from '../components/Card';
import { RuleTestPanel } from '../components/detection/RuleTestPanel';
import { PageHeader } from '../components/PageHeader';
import { SeverityBadge } from '../components/SeverityBadge';
import { Switch } from '../components/Switch';

const TYPE_LABELS: Record<RuleDetail['rule_type'], string> = {
  match: 'Single event match',
  threshold: 'Threshold',
  sequence: 'Sequence',
  new_value: 'New value',
};

function RuleFacts({ rule }: { rule: RuleDetail }) {
  const toggle = useToggleRule();

  return (
    <Card
      title="Rule"
      aside={
        <span className="inline-field">
          <span className="muted small">{rule.enabled ? 'Enabled' : 'Disabled'}</span>
          <Switch
            checked={rule.enabled}
            label={`${rule.enabled ? 'Disable' : 'Enable'} this rule`}
            disabled={toggle.isPending}
            onChange={(enabled) => {
              toggle.mutate({ id: rule.id, enabled });
            }}
          />
        </span>
      }
    >
      <p className="prose">{rule.description}</p>
      <dl className="facts">
        <div>
          <dt>Severity</dt>
          <dd>
            <SeverityBadge severity={rule.severity} />
          </dd>
        </div>
        <div>
          <dt>Type</dt>
          <dd>{TYPE_LABELS[rule.rule_type]}</dd>
        </div>
        <div>
          <dt>Grouped by</dt>
          <dd className="mono">{rule.group_by.join(', ') || 'host.name'}</dd>
        </div>
        <div>
          <dt>Log sources</dt>
          <dd className="mono">{rule.log_sources.join(', ') || 'all'}</dd>
        </div>
        <div>
          <dt>Open / total alerts</dt>
          <dd>
            <Link className="link" to={`/alerts?rule=${rule.id}`}>
              {rule.open_alerts} / {rule.total_alerts}
            </Link>
          </dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd>
            {rule.version}
            {rule.origin === 'custom'
              ? ' (custom)'
              : rule.modified
                ? ' (edited built-in)'
                : ' (built-in)'}
          </dd>
        </div>
      </dl>
      <h3 className="subheading">ATT&amp;CK</h3>
      <ul className="plain-list">
        {rule.tactics.map((tactic) => (
          <li key={tactic.id}>
            <span className="badge">{tactic.id}</span> {tactic.name}
          </li>
        ))}
        {rule.techniques.map((technique) => (
          <li key={technique.id}>
            <a
              className="link"
              href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
              target="_blank"
              rel="noreferrer"
            >
              {technique.id}
            </a>{' '}
            {technique.name}
          </li>
        ))}
      </ul>
      {rule.false_positives.length > 0 ? (
        <>
          <h3 className="subheading">Known false positives</h3>
          <ul className="plain-list bullets">
            {rule.false_positives.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </>
      ) : null}
    </Card>
  );
}

function RuleEditor({
  rule,
  source,
  onChange,
}: {
  rule: RuleDetail;
  source: string;
  onChange: (text: string) => void;
}) {
  const save = useSaveRule(rule.id);
  const validate = useValidateRule();
  const editorId = useId();
  const dirty = source !== rule.source_yaml;

  return (
    <Card title="Definition (YAML)">
      <label htmlFor={editorId} className="visually-hidden">
        Rule YAML
      </label>
      <textarea
        id={editorId}
        className="code-input"
        rows={24}
        spellCheck={false}
        value={source}
        onChange={(event) => {
          onChange(event.target.value);
          validate.reset();
          save.reset();
        }}
      />
      {rule.origin === 'builtin' && dirty ? (
        <p className="muted small">
          Saving marks this built-in rule as edited, so future rule updates will not overwrite your
          changes.
        </p>
      ) : null}
      <div className="inline-field">
        <button
          type="button"
          className="button button--secondary"
          disabled={validate.isPending}
          onClick={() => {
            validate.mutate(source);
          }}
        >
          Validate
        </button>
        <button
          type="button"
          className="button"
          disabled={!dirty || save.isPending}
          onClick={() => {
            save.mutate(source);
          }}
        >
          {save.isPending ? 'Saving…' : 'Save changes'}
        </button>
        {dirty ? (
          <button
            type="button"
            className="button button--secondary"
            onClick={() => {
              onChange(rule.source_yaml);
            }}
          >
            Discard
          </button>
        ) : null}
      </div>
      {validate.data ? (
        <p className={validate.data.valid ? 'text-ok' : 'text-error'} role="status">
          {validate.data.valid ? 'The rule is valid.' : validate.data.error}
        </p>
      ) : null}
      {save.isError ? (
        <p className="text-error" role="alert">
          {save.error.message}
        </p>
      ) : null}
      {save.isSuccess && !dirty ? (
        <p className="text-ok" role="status">
          Saved as version {rule.version}.
        </p>
      ) : null}
    </Card>
  );
}

function RuleWorkspace({ rule }: { rule: RuleDetail }) {
  // Keyed by version in the parent, so a save resets the editor to the saved text.
  const [source, setSource] = useState(rule.source_yaml);

  return (
    <div className="rule-layout">
      <div className="stack stack--flush">
        <RuleFacts rule={rule} />
        <RuleTestPanel sourceYaml={source} />
      </div>
      <RuleEditor rule={rule} source={source} onChange={setSource} />
    </div>
  );
}

export function RuleDetailPage() {
  const { ruleId = '' } = useParams();
  const rule = useRule(ruleId);

  return (
    <>
      <p className="breadcrumb">
        <Link className="link" to="/rules">
          ← All rules
        </Link>
      </p>
      <PageHeader
        title={rule.data?.title ?? ruleId}
        description={rule.data ? `Rule ${rule.data.id}` : 'Loading rule…'}
      />
      {rule.isError ? <p className="text-error">{rule.error.message}</p> : null}
      {rule.data ? <RuleWorkspace key={rule.data.version} rule={rule.data} /> : null}
    </>
  );
}
