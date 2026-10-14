import { useEnrichAlert } from '../../api/queries';
import type { AlertDetail } from '../../api/types';
import { formatUtc } from '../../lib/format';
import { IOC_TYPE_LABELS, isEnriched } from '../../lib/intel';
import { LocalIntel, ProviderResults } from './IndicatorContext';
import { VerdictBadge } from './VerdictBadge';

interface EnrichmentPanelProps {
  alertId: number;
  enrichment: AlertDetail['enrichment'];
}

/** The indicators behind an alert and what is known about each. */
export function EnrichmentPanel({ alertId, enrichment }: EnrichmentPanelProps) {
  const enrich = useEnrichAlert(alertId);
  const error = enrich.isError ? (
    <p className="text-error small" role="alert">
      {enrich.error.message}
    </p>
  ) : null;

  if (!isEnriched(enrichment)) {
    return (
      <section className="enrichment" aria-label="Threat intelligence">
        <div className="enrichment__header">
          <h3 className="subheading">Threat intelligence</h3>
          <span className="muted small">Not checked yet.</span>
          <button
            type="button"
            className="button button--secondary button--small"
            disabled={enrich.isPending}
            onClick={() => {
              enrich.mutate(false);
            }}
          >
            {enrich.isPending ? 'Checking…' : 'Check indicators'}
          </button>
        </div>
        {error}
      </section>
    );
  }

  return (
    <section className="enrichment" aria-label="Threat intelligence">
      <div className="enrichment__header">
        <h3 className="subheading">Threat intelligence</h3>
        <VerdictBadge verdict={enrichment.verdict} />
        <span className="muted small">
          Checked {formatUtc(enrichment.enriched_at)}
          {enrichment.online ? '' : ' · local indicators only'}
        </span>
        <button
          type="button"
          className="button button--secondary button--small"
          disabled={enrich.isPending}
          onClick={() => {
            enrich.mutate(true);
          }}
        >
          {enrich.isPending ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>
      {error}
      {enrichment.pending ? (
        <p className="text-warn small">
          Some lookups are waiting on a provider&apos;s rate limit and will be retried
          automatically.
        </p>
      ) : null}
      {enrichment.indicators.length === 0 ? (
        <p className="muted small">
          No IP addresses, domains or file hashes in this alert&apos;s evidence.
        </p>
      ) : (
        <ul className="indicator-list">
          {enrichment.indicators.map((indicator) => (
            <li key={`${indicator.type}:${indicator.value}`} className="indicator">
              <div className="indicator__head">
                <span className="mono indicator__value">{indicator.value}</span>
                <span className="badge">{IOC_TYPE_LABELS[indicator.type]}</span>
                <VerdictBadge verdict={indicator.verdict} />
                <span className="muted small">seen in {indicator.fields.join(', ')}</span>
              </div>
              <LocalIntel hits={indicator.intel} />
              {indicator.providers.length > 0 ? (
                <ProviderResults results={indicator.providers} />
              ) : null}
              {!indicator.shared && enrichment.online ? (
                <p className="muted small">
                  Internal or reserved, so never sent to online providers.
                </p>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
