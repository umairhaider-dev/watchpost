import type {
  AlertDetail,
  AlertEnrichment,
  IocType,
  LookupStatus,
  ProviderLookup,
} from '../api/types';

export const IOC_TYPE_LABELS: Record<IocType, string> = {
  ip: 'IP',
  domain: 'Domain',
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
};

export const LOOKUP_STATUS_LABELS: Record<LookupStatus, string> = {
  ok: 'Answered',
  not_found: 'No record',
  error: 'Failed',
  rate_limited: 'Postponed',
};

export function isEnriched(enrichment: AlertDetail['enrichment']): enrichment is AlertEnrichment {
  return typeof enrichment.enriched_at === 'string';
}

function numberField(data: Record<string, unknown>, key: string): number | null {
  const value = data[key];
  return typeof value === 'number' ? value : null;
}

function textField(data: Record<string, unknown>, key: string): string | null {
  const value = data[key];
  return typeof value === 'string' && value ? value : null;
}

function joinParts(parts: (string | null)[]): string {
  return parts.filter((part): part is string => part !== null).join(' · ');
}

/** One readable line about a provider's answer. */
export function describeLookup(result: ProviderLookup): string {
  const { data } = result;
  if (result.status === 'not_found') return 'No record of this indicator';
  if (result.status === 'rate_limited') return 'Waiting on the rate limit; retried automatically';
  if (result.status === 'error') return textField(data, 'error') ?? 'The lookup failed';

  if (result.provider === 'abuseipdb') {
    const score = numberField(data, 'score');
    const reports = numberField(data, 'reports');
    return joinParts([
      score !== null ? `abuse score ${String(score)}%` : null,
      reports !== null ? `${String(reports)} report${reports === 1 ? '' : 's'}` : null,
      textField(data, 'country'),
      textField(data, 'isp'),
      data.is_tor === true ? 'Tor exit node' : null,
    ]);
  }
  if (result.provider === 'virustotal') {
    const counts = ['malicious', 'suspicious', 'harmless', 'undetected'].map(
      (key) => numberField(data, key) ?? 0,
    );
    const engines = counts.reduce((sum, count) => sum + count, 0);
    return joinParts([
      `${String(counts[0] ?? 0)} of ${String(engines)} engines flag it`,
      textField(data, 'name'),
      textField(data, 'file_type'),
      textField(data, 'as_owner'),
      textField(data, 'registrar'),
    ]);
  }
  return '';
}

/** A provider's own page for the indicator, if it gave one. */
export function lookupLink(result: ProviderLookup): string | null {
  const link = textField(result.data, 'link');
  return link?.startsWith('https://') ? link : null;
}
