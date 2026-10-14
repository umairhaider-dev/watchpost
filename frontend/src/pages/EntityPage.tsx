import { Link, useParams, useSearchParams } from 'react-router';

import { useEntity } from '../api/investigation';
import type { Counted, EntityKind, EntityProfile } from '../api/types';
import { Card } from '../components/Card';
import { EntityLink } from '../components/EntityLink';
import { PageHeader } from '../components/PageHeader';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertStatusBadge, CaseStatusBadge } from '../components/StatusBadges';
import { formatNumber, formatUtc } from '../lib/format';
import { NotFoundPage } from './NotFoundPage';

const KINDS: Record<EntityKind, string> = { ip: 'IP address', user: 'User', host: 'Host' };
const RELATED_LABELS = { users: 'Users', hosts: 'Hosts', ips: 'IP addresses' } as const;
const RELATED_KINDS = { users: 'user', hosts: 'host', ips: 'ip' } as const;

function isKind(value: string | undefined): value is EntityKind {
  return value === 'ip' || value === 'user' || value === 'host';
}

function ActivityBars({ days }: { days: EntityProfile['activity'] }) {
  const peak = Math.max(1, ...days.map((day) => day.count));
  return (
    <div className="bars" role="img" aria-label="Events per day">
      {days.map((day) => (
        <span
          key={day.day}
          className="bars__bar"
          style={{ height: `${String(Math.max(4, (day.count / peak) * 100))}%` }}
          title={`${day.day.slice(0, 10)}: ${String(day.count)} events`}
        />
      ))}
    </div>
  );
}

function RelatedList({ kind, items }: { kind: EntityKind; items: Counted[] }) {
  if (items.length === 0) return <p className="muted small">None seen.</p>;
  return (
    <ul className="plain-list small">
      {items.map((item) => (
        <li key={item.value} className="related-row">
          <EntityLink kind={kind} value={item.value} />
          <span className="muted">{formatNumber(item.count)}</span>
        </li>
      ))}
    </ul>
  );
}

function Profile({ profile }: { profile: EntityProfile }) {
  const searchLink = `/events?${new URLSearchParams({ q: profile.query }).toString()}`;
  return (
    <>
      <div className="grid grid--wide">
        <Card
          title="Activity"
          aside={
            <Link className="link small" to={searchLink}>
              Search its events
            </Link>
          }
        >
          {profile.event_count === 0 ? (
            <p className="muted">
              No stored events involve this {KINDS[profile.kind].toLowerCase()}.
            </p>
          ) : (
            <>
              <dl className="stat-row">
                <div>
                  <dt>Events</dt>
                  <dd>{formatNumber(profile.event_count)}</dd>
                </div>
                <div>
                  <dt>First seen</dt>
                  <dd className="mono small">
                    {profile.first_seen ? formatUtc(profile.first_seen) : '—'}
                  </dd>
                </div>
                <div>
                  <dt>Last seen</dt>
                  <dd className="mono small">
                    {profile.last_seen ? formatUtc(profile.last_seen) : '—'}
                  </dd>
                </div>
              </dl>
              <ActivityBars days={profile.activity} />
              <p className="muted small">
                Sources:{' '}
                {profile.log_sources
                  .map((source) => `${source.value} (${formatNumber(source.count)})`)
                  .join(', ')}
              </p>
            </>
          )}
        </Card>
        <Card title="Seen with">
          {(Object.keys(RELATED_LABELS) as (keyof typeof RELATED_LABELS)[])
            .filter((key) => profile.related[key] !== undefined)
            .map((key) => (
              <div key={key}>
                <h3 className="subheading">{RELATED_LABELS[key]}</h3>
                <RelatedList kind={RELATED_KINDS[key]} items={profile.related[key] ?? []} />
              </div>
            ))}
          {profile.event_count === 0 ? <p className="muted small">Nothing yet.</p> : null}
        </Card>
      </div>
      {profile.intel.length > 0 ? (
        <div className="stack">
          <Card title="Threat intel">
            <ul className="plain-list small">
              {profile.intel.map((ioc) => (
                <li key={ioc.id}>
                  <span className="ioc-flag">IOC</span> {ioc.description ?? 'Listed as malicious'}{' '}
                  <span className="muted">
                    · {ioc.source}
                    {ioc.confidence !== null ? ` · confidence ${String(ioc.confidence)}` : ''}
                  </span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      ) : null}
      <div className="stack">
        <Card
          title={`Alerts (${formatNumber(profile.alert_count)}, ${formatNumber(profile.open_alert_count)} open)`}
        >
          {profile.alerts.length === 0 ? (
            <p className="muted">No alerts involve this entity.</p>
          ) : (
            <div className="table-wrap">
              <table className="table table--compact">
                <thead>
                  <tr>
                    <th scope="col">Alert</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Status</th>
                    <th scope="col">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {profile.alerts.map((alert) => (
                    <tr key={alert.id}>
                      <td>
                        <Link className="link" to={`/alerts/${String(alert.id)}`}>
                          {alert.title}
                        </Link>
                      </td>
                      <td>
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td>
                        <AlertStatusBadge status={alert.status} />
                      </td>
                      <td className="mono nowrap small">{formatUtc(alert.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        {profile.cases.length > 0 ? (
          <Card title="Cases">
            <ul className="plain-list small">
              {profile.cases.map((item) => (
                <li key={item.id} className="related-row">
                  <Link className="link" to={`/cases/${String(item.id)}`}>
                    #{item.id} {item.title}
                  </Link>
                  <CaseStatusBadge status={item.status} />
                </li>
              ))}
            </ul>
          </Card>
        ) : null}
      </div>
    </>
  );
}

export function EntityPage() {
  const { kind } = useParams();
  const [params] = useSearchParams();
  const value = params.get('value') ?? '';
  const entity = useEntity(isKind(kind) ? kind : 'host', isKind(kind) ? value : '');

  if (!isKind(kind) || !value.trim()) return <NotFoundPage />;
  return (
    <>
      <PageHeader title={`${KINDS[kind]} ${value}`} />
      {entity.isPending ? <p className="muted">Loading…</p> : null}
      {entity.isError ? (
        <p className="text-error" role="alert">
          {entity.error.message}
        </p>
      ) : null}
      {entity.data ? <Profile profile={entity.data} /> : null}
    </>
  );
}
