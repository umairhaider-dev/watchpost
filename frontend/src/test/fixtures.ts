import type {
  AlertEnrichment,
  AlertSummary,
  DetectionRun,
  Ioc,
  ProviderLookup,
  RuleDetail,
  RuleSummary,
} from '../api/types';

export function ruleSummary(overrides: Partial<RuleSummary> = {}): RuleSummary {
  return {
    id: 'ssh-brute-force',
    title: 'SSH brute force',
    severity: 'medium',
    rule_type: 'threshold',
    origin: 'builtin',
    enabled: true,
    modified: false,
    version: 1,
    tactics: [{ id: 'TA0006', name: 'Credential Access' }],
    techniques: [{ id: 'T1110.001', name: 'Brute Force: Password Guessing' }],
    open_alerts: 1,
    total_alerts: 2,
    last_alert_at: '2026-10-12T09:02:51Z',
    updated_at: '2026-10-12T08:00:00Z',
    ...overrides,
  };
}

export const RULE_YAML = `id: ssh-brute-force
title: SSH brute force
description: Many failed SSH logins from one address.
severity: medium
type: threshold
detection:
  failed_login:
    event.action: ssh_login
    event.outcome: failure
  condition: failed_login
group_by: [source.ip]
threshold:
  count: 10
  timeframe: 5m
`;

export function ruleDetail(overrides: Partial<RuleDetail> = {}): RuleDetail {
  return {
    ...ruleSummary(),
    description: 'Many failed SSH logins from one address.',
    false_positives: ['Users retrying an expired password'],
    references: ['https://attack.mitre.org/techniques/T1110/001/'],
    source_yaml: RULE_YAML,
    group_by: ['source.ip'],
    log_sources: ['linux_auth'],
    ...overrides,
  };
}

export function detectionRun(overrides: Partial<DetectionRun> = {}): DetectionRun {
  return {
    id: 4,
    trigger: 'manual',
    status: 'completed',
    ingest_job_id: null,
    rule_ids: null,
    range_start: '2026-10-05T00:00:00Z',
    range_end: null,
    events_scanned: 1500,
    hits: 3,
    alerts_created: 2,
    alerts_updated: 1,
    error: null,
    created_at: '2026-10-12T10:00:00Z',
    started_at: '2026-10-12T10:00:00Z',
    finished_at: '2026-10-12T10:00:02Z',
    ...overrides,
  };
}

export function alertSummary(overrides: Partial<AlertSummary> = {}): AlertSummary {
  return {
    id: 11,
    rule_id: 'ssh-brute-force',
    title: 'SSH brute force: 203.0.113.45',
    severity: 'medium',
    status: 'new',
    first_seen: '2026-10-12T09:02:13Z',
    last_seen: '2026-10-12T09:02:51Z',
    event_count: 10,
    host_name: 'web-01',
    source_ip: '203.0.113.45',
    user_name: 'root',
    mitre_tactics: ['TA0006'],
    mitre_techniques: ['T1110.001'],
    case_id: null,
    created_at: '2026-10-12T09:05:00Z',
    updated_at: '2026-10-12T09:05:00Z',
    ...overrides,
  };
}

export const MIMIKATZ_SHA256 = '3c1f1a2b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a';

export function ioc(overrides: Partial<Ioc> = {}): Ioc {
  return {
    id: 1,
    ioc_type: 'ip',
    value: '203.0.113.45',
    source: 'iocs.csv',
    description: 'SSH brute-force source reported by several organisations',
    confidence: 85,
    tags: ['brute-force', 'ssh'],
    is_active: true,
    expires_at: null,
    created_at: '2026-10-14T08:00:00Z',
    updated_at: '2026-10-14T08:00:00Z',
    match_count: 12,
    last_matched_at: '2026-10-14T08:00:05Z',
    ...overrides,
  };
}

export function virusTotalAnswer(overrides: Partial<ProviderLookup> = {}): ProviderLookup {
  return {
    provider: 'virustotal',
    label: 'VirusTotal',
    status: 'ok',
    verdict: 'malicious',
    data: {
      malicious: 52,
      suspicious: 1,
      harmless: 0,
      undetected: 17,
      name: 'm.exe',
      file_type: 'Win32 EXE',
      link: `https://www.virustotal.com/gui/file/${MIMIKATZ_SHA256}`,
    },
    fetched_at: '2026-10-14T09:00:00Z',
    cached: false,
    ...overrides,
  };
}

export function enrichment(overrides: Partial<AlertEnrichment> = {}): AlertEnrichment {
  return {
    enriched_at: '2026-10-14T09:00:00Z',
    verdict: 'malicious',
    pending: false,
    online: true,
    indicators: [
      {
        type: 'ip',
        value: '203.0.113.45',
        fields: ['source.ip'],
        verdict: 'malicious',
        shared: false,
        intel: [
          {
            id: 1,
            type: 'ip',
            value: '203.0.113.45',
            source: 'iocs.csv',
            description: 'SSH brute-force source reported by several organisations',
            confidence: 85,
            tags: ['brute-force', 'ssh'],
          },
        ],
        providers: [],
      },
      {
        type: 'sha256',
        value: MIMIKATZ_SHA256,
        fields: ['Hashes'],
        verdict: 'malicious',
        shared: true,
        intel: [],
        providers: [virusTotalAnswer()],
      },
    ],
    ...overrides,
  };
}
