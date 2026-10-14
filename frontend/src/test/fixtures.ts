import type {
  AlertDetail,
  AlertEnrichment,
  AlertSummary,
  AuditEntry,
  CaseDetail,
  CaseSummary,
  CurrentUser,
  Dashboard,
  DetectionRun,
  EventRecord,
  Ioc,
  ProviderLookup,
  RuleDetail,
  RuleSummary,
  User,
  UserAccount,
  UserRole,
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
    assignee_id: null,
    resolved_at: null,
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

export function eventRecord(id: number, overrides: Partial<EventRecord> = {}): EventRecord {
  return {
    id,
    timestamp: '2026-10-12T09:02:13Z',
    ingested_at: '2026-10-13T08:00:00Z',
    log_source: 'linux_auth',
    host_name: 'web-01',
    source_ip: '203.0.113.45',
    source_port: 40112,
    destination_ip: null,
    destination_port: null,
    user_name: 'root',
    event_category: 'authentication',
    event_action: 'ssh_login',
    event_outcome: 'failure',
    event_code: null,
    process_name: 'sshd',
    process_pid: 3101,
    process_executable: null,
    process_command_line: null,
    process_parent_name: null,
    process_parent_pid: null,
    url_original: null,
    http_method: null,
    http_status_code: null,
    user_agent: null,
    message: 'Failed password for root from 203.0.113.45 port 40112 ssh2',
    ioc_matched: false,
    raw_event: { line: `raw line ${String(id)}` },
    ...overrides,
  };
}

export function alertDetail(overrides: Partial<AlertDetail> = {}): AlertDetail {
  return {
    ...alertSummary(),
    enrichment: {},
    rule: {
      id: 'ssh-brute-force',
      title: 'SSH brute force',
      description: 'Many failed SSH logins from one address.',
      false_positives: ['Users retrying an expired password'],
    },
    evidence: [eventRecord(1)],
    activity: [],
    ...overrides,
  };
}

export function analyst(overrides: Partial<User> = {}): User {
  return {
    id: 3,
    username: 'analyst.one',
    full_name: 'Analyst One',
    role: 'analyst',
    is_active: true,
    ...overrides,
  };
}

/** A signed-in user with the given role, for ``stubApi(..., { user })``. */
export function signedInAs(role: UserRole): CurrentUser {
  return {
    id: 3,
    username: `${role}.one`,
    full_name: null,
    email: null,
    role,
  };
}

export function userAccount(overrides: Partial<UserAccount> = {}): UserAccount {
  return {
    id: 3,
    username: 'analyst.one',
    full_name: 'Analyst One',
    email: 'analyst.one@example.org',
    role: 'analyst',
    is_active: true,
    last_login_at: '2026-10-14T08:30:00Z',
    created_at: '2026-10-01T09:00:00Z',
    ...overrides,
  };
}

export function auditEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: 1,
    occurred_at: '2026-10-14T09:15:00Z',
    user_id: 1,
    username: 'test.admin',
    action: 'rule.disabled',
    target_type: 'rule',
    target_id: 'ssh-brute-force',
    details: {},
    ip_address: '10.20.0.5',
    user_agent: 'Mozilla/5.0',
    ...overrides,
  };
}

export function caseSummary(overrides: Partial<CaseSummary> = {}): CaseSummary {
  return {
    id: 7,
    title: 'SSH brute force on web-01',
    severity: 'high',
    status: 'open',
    assignee_id: null,
    created_by_id: null,
    created_at: '2026-10-12T09:10:00Z',
    updated_at: '2026-10-12T09:20:00Z',
    resolved_at: null,
    closed_at: null,
    alert_count: 1,
    open_alert_count: 1,
    note_count: 0,
    evidence_count: 0,
    ...overrides,
  };
}

export function caseDetail(overrides: Partial<CaseDetail> = {}): CaseDetail {
  return {
    ...caseSummary(),
    description: 'Brute force from 203.0.113.45 ended in a login as backup.',
    resolution: null,
    assignee: null,
    created_by: null,
    alerts: [alertSummary({ case_id: 7, status: 'investigating' })],
    notes: [],
    evidence: [],
    activity: [],
    tactics: ['TA0006'],
    techniques: ['T1110.001'],
    entities: { hosts: ['web-01'], ips: ['203.0.113.45'], users: ['root'] },
    ...overrides,
  };
}

/** ``count`` consecutive hourly bucket starts. */
function hourly(count: number): string[] {
  const start = Date.parse('2026-10-14T00:00:00Z');
  return Array.from({ length: count }, (_, index) =>
    new Date(start + index * 3_600_000).toISOString(),
  );
}

export function dashboard(overrides: Partial<Dashboard> = {}): Dashboard {
  const buckets = hourly(4);
  return {
    range: '24h',
    start: '2026-10-13T04:00:00Z',
    end: '2026-10-14T04:00:00Z',
    bucket_seconds: 3600,
    totals: {
      alerts: 6,
      open_alerts: 4,
      new_alerts: 3,
      unassigned_open_alerts: 2,
      open_cases: 1,
      events: 1234,
    },
    alerts_over_time: buckets.map((bucket, index) => ({
      bucket,
      critical: index === 1 ? 1 : 0,
      high: 0,
      medium: index === 2 ? 4 : 0,
      low: index === 3 ? 1 : 0,
      informational: 0,
    })),
    alerts_by_severity: [
      { severity: 'critical', count: 1, open: 1 },
      { severity: 'high', count: 0, open: 0 },
      { severity: 'medium', count: 4, open: 3 },
      { severity: 'low', count: 1, open: 0 },
      { severity: 'informational', count: 0, open: 0 },
    ],
    top_source_ips: [
      { value: '203.0.113.45', alerts: 4, events: 31, known_bad: true },
      { value: '198.51.100.23', alerts: 1, events: 12, known_bad: false },
    ],
    top_users: [{ value: 'root', alerts: 3, events: 20, known_bad: false }],
    top_rules: [
      { rule_id: 'ssh-brute-force', title: 'SSH brute force', severity: 'medium', alerts: 3 },
    ],
    ingestion: {
      series: buckets.map((bucket, index) => ({
        bucket,
        events: index === 0 ? 1234 : 0,
        jobs: index === 0 ? 2 : 0,
      })),
      events_ingested: 1234,
      jobs: 2,
      events_per_second: 617.4,
    },
    case_resolution: { resolved: 2, mean_seconds: 14_400, median_seconds: 7_200 },
    alert_resolution: { resolved: 0, mean_seconds: null, median_seconds: null },
    ...overrides,
  };
}
