import { useProviders } from '../../api/queries';
import { Card } from '../Card';

export function ProvidersCard() {
  const providers = useProviders();
  const data = providers.data;

  return (
    <Card title="Online lookups">
      {providers.isError ? <p className="text-error">Could not load provider status.</p> : null}
      {data ? (
        <>
          <ul className="context-list">
            {data.providers.map((provider) => (
              <li key={provider.name}>
                <span className="context-list__name">{provider.label}</span>
                <span className="pill" data-status={provider.configured ? 'completed' : undefined}>
                  {provider.configured ? 'Configured' : 'Not configured'}
                </span>
                {provider.cooling_down ? (
                  <span className="text-warn small">Paused by the provider&apos;s rate limit</span>
                ) : null}
                {provider.configured ? (
                  <span className="muted small">
                    {Object.entries(provider.remaining)
                      .map(([window, left]) => `${String(left)} left of ${window}`)
                      .join(' · ')}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
          <p className="muted small">
            {data.online
              ? `Public IPs, domains and file hashes in alerts are looked up and cached for ${String(data.cache_hours)} hours.`
              : 'Working offline: alerts are checked against the local indicator store only. Set WATCHPOST_ABUSEIPDB_API_KEY or WATCHPOST_VIRUSTOTAL_API_KEY to add online lookups.'}{' '}
            Private, internal and documentation addresses are never sent.
          </p>
        </>
      ) : null}
    </Card>
  );
}
