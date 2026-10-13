import { useHealth, useReadiness } from '../api/queries';
import type { DependencyCheck } from '../api/types';
import { Card } from '../components/Card';
import { PageHeader } from '../components/PageHeader';
import { StatusIndicator, type StatusTone } from '../components/StatusIndicator';

const DEPENDENCIES = [
  { key: 'database', label: 'PostgreSQL', role: 'Stores events, alerts, cases and rules.' },
  { key: 'redis', label: 'Redis', role: 'Job queue for ingestion and detection.' },
] as const;

function overallStatus(readiness: ReturnType<typeof useReadiness>): [StatusTone, string] {
  if (readiness.isPending) return ['unknown', 'Checking…'];
  if (readiness.isError) return ['error', 'API unreachable'];
  return readiness.data.status === 'ok' ? ['ok', 'Operational'] : ['warn', 'Degraded'];
}

function DependencyCard({
  label,
  role,
  check,
}: {
  label: string;
  role: string;
  check: DependencyCheck | undefined;
}) {
  let indicator = <StatusIndicator tone="unknown" label="Unknown" />;
  if (check?.status === 'ok') indicator = <StatusIndicator tone="ok" label="Healthy" />;
  if (check?.status === 'error') indicator = <StatusIndicator tone="error" label="Unavailable" />;

  return (
    <Card title={label} aside={indicator}>
      <p className="muted">{role}</p>
      <dl className="facts">
        <div>
          <dt>Latency</dt>
          <dd>{check?.latency_ms != null ? `${check.latency_ms.toFixed(1)} ms` : '—'}</dd>
        </div>
        {check?.error ? (
          <div>
            <dt>Error</dt>
            <dd className="text-error">{check.error}</dd>
          </div>
        ) : null}
      </dl>
    </Card>
  );
}

export function OverviewPage() {
  const health = useHealth();
  const readiness = useReadiness();
  const [tone, label] = overallStatus(readiness);
  const checkedAt = readiness.dataUpdatedAt
    ? new Date(readiness.dataUpdatedAt).toLocaleTimeString()
    : '—';

  return (
    <>
      <PageHeader
        title="Overview"
        description="Platform health and the services Watchpost depends on."
      />
      <div className="grid">
        <Card title="Platform" aside={<StatusIndicator tone={tone} label={label} />}>
          <dl className="facts">
            <div>
              <dt>Version</dt>
              <dd className="mono">{health.data?.version ?? '—'}</dd>
            </div>
            <div>
              <dt>Environment</dt>
              <dd>{health.data?.environment ?? '—'}</dd>
            </div>
            <div>
              <dt>Last checked</dt>
              <dd>{checkedAt}</dd>
            </div>
          </dl>
        </Card>
        {DEPENDENCIES.map((dep) => (
          <DependencyCard
            key={dep.key}
            label={dep.label}
            role={dep.role}
            check={readiness.data?.checks[dep.key]}
          />
        ))}
      </div>
    </>
  );
}
