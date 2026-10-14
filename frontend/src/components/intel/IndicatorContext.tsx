import type { IntelHit, ProviderLookup } from '../../api/types';
import { describeLookup, LOOKUP_STATUS_LABELS, lookupLink } from '../../lib/intel';
import { VerdictBadge } from './VerdictBadge';

type LocalHit = Pick<IntelHit, 'id' | 'source' | 'description' | 'confidence' | 'tags'>;

/** What the local indicator store says about an indicator. */
export function LocalIntel({ hits }: { hits: LocalHit[] }) {
  if (hits.length === 0) {
    return <p className="muted small">Not in the local indicator store.</p>;
  }
  return (
    <ul className="context-list">
      {hits.map((hit) => (
        <li key={hit.id}>
          <span className="context-list__name">Local intel</span>
          <span className="small">
            {hit.description ?? 'Listed as malicious'}
            <span className="muted">
              {' '}
              · {hit.source}
              {hit.confidence !== null ? ` · confidence ${String(hit.confidence)}` : ''}
            </span>
          </span>
          {hit.tags.length > 0 ? (
            <span className="tag-list">
              {hit.tags.map((tag) => (
                <span key={tag} className="badge">
                  {tag}
                </span>
              ))}
            </span>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

/** Answers from online reputation providers. */
export function ProviderResults({ results }: { results: ProviderLookup[] }) {
  return (
    <ul className="context-list">
      {results.map((result) => {
        const link = lookupLink(result);
        return (
          <li key={result.provider}>
            <span className="context-list__name">{result.label}</span>
            {result.status === 'ok' ? (
              <VerdictBadge verdict={result.verdict} />
            ) : (
              <span className="pill" data-lookup={result.status}>
                {LOOKUP_STATUS_LABELS[result.status]}
              </span>
            )}
            <span className="muted small">{describeLookup(result)}</span>
            {link ? (
              <a className="link small" href={link} target="_blank" rel="noreferrer noopener">
                Open in {result.label}
              </a>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
