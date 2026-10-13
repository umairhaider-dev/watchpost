import type { AlertSummary, DetectionRun, RuleDetail, RuleSummary } from '../api/types';

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
