// Response shapes of the Watchpost API. Keep in sync with the Pydantic models
// in backend/src/watchpost/api/routes.

export interface HealthResponse {
  status: 'ok';
  version: string;
  environment: string;
}

export interface DependencyCheck {
  status: 'ok' | 'error';
  latency_ms: number | null;
  error: string | null;
}

export interface ReadinessResponse {
  status: 'ok' | 'degraded';
  checks: Record<string, DependencyCheck>;
}

export type FieldKind = 'keyword' | 'text' | 'ip' | 'integer' | 'datetime';

export interface FieldInfo {
  name: string;
  kind: FieldKind;
  description: string;
}

// ---------------------------------------------------------------- ingestion

export interface ParserInfo {
  name: string;
  label: string;
  description: string;
  input_format: 'lines' | 'json';
}

export interface IngestInfo {
  parsers: ParserInfo[];
  max_upload_bytes: number;
  watch_enabled: boolean;
  watch_interval_seconds: number;
}

export type IngestStatus = 'queued' | 'running' | 'completed' | 'failed';
export type IngestOrigin = 'upload' | 'watch_folder';

export interface IngestionJob {
  id: number;
  origin: IngestOrigin;
  status: IngestStatus;
  filename: string;
  parser: string;
  detected_parser: string | null;
  host_name: string | null;
  file_size: number;
  bytes_processed: number;
  records_read: number;
  events_inserted: number;
  events_duplicate: number;
  records_malformed: number;
  records_skipped: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  detection?: DetectionSummary | null;
}

export interface DetectionSummary {
  id: number;
  status: DetectionStatus;
  hits: number;
  alerts_created: number;
  alerts_updated: number;
}

export interface MalformedSample {
  line: number;
  reason: string;
  excerpt: string;
}

export interface IngestionJobDetail extends IngestionJob {
  malformed_samples: MalformedSample[];
}

export interface IngestionJobPage {
  items: IngestionJob[];
  total: number;
}

// ---------------------------------------------------------------- events

export type LogSource = 'linux_auth' | 'windows_security' | 'sysmon' | 'web_access' | 'json';

export interface EventRecord {
  id: number;
  timestamp: string;
  ingested_at: string;
  log_source: LogSource;
  host_name: string | null;
  source_ip: string | null;
  source_port: number | null;
  destination_ip: string | null;
  destination_port: number | null;
  user_name: string | null;
  event_category: string | null;
  event_action: string | null;
  event_outcome: 'success' | 'failure' | 'unknown' | null;
  event_code: string | null;
  process_name: string | null;
  process_pid: number | null;
  process_executable: string | null;
  process_command_line: string | null;
  process_parent_name: string | null;
  process_parent_pid: number | null;
  url_original: string | null;
  http_method: string | null;
  http_status_code: number | null;
  user_agent: string | null;
  message: string | null;
  ioc_matched: boolean;
  raw_event: Record<string, unknown>;
}

export interface EventPage {
  items: EventRecord[];
  next_cursor: string | null;
}

// ---------------------------------------------------------------- detection

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type RuleType = 'match' | 'threshold' | 'sequence' | 'new_value';
export type RuleOrigin = 'builtin' | 'custom';
export type DetectionStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface MitreRef {
  id: string;
  name: string | null;
}

export interface RuleSummary {
  id: string;
  title: string;
  severity: Severity;
  rule_type: RuleType;
  origin: RuleOrigin;
  enabled: boolean;
  modified: boolean;
  version: number;
  tactics: MitreRef[];
  techniques: MitreRef[];
  open_alerts: number;
  total_alerts: number;
  last_alert_at: string | null;
  updated_at: string;
}

export interface RuleDetail extends RuleSummary {
  description: string;
  false_positives: string[];
  references: string[];
  source_yaml: string;
  group_by: string[];
  log_sources: string[];
}

export interface RuleValidation {
  valid: boolean;
  error: string | null;
  id: string | null;
  title: string | null;
  rule_type: RuleType | null;
}

export interface RuleTestHit {
  title: string;
  group: Record<string, string | null>;
  event_count: number;
  first_seen: string;
  last_seen: string;
  lines: number[];
}

export interface RuleTestEvent {
  line: number;
  timestamp: string;
  event_action: string | null;
  event_outcome: string | null;
  host_name: string | null;
  user_name: string | null;
  source_ip: string | null;
  message: string | null;
}

export interface RuleTestResult {
  parser: string;
  events_parsed: number;
  truncated: boolean;
  malformed_count: number;
  malformed: MalformedSample[];
  hits: RuleTestHit[];
  matched_events: RuleTestEvent[];
}

export interface DetectionRun {
  id: number;
  trigger: 'ingestion' | 'manual' | 'intel';
  status: DetectionStatus;
  ingest_job_id: number | null;
  rule_ids: string[] | null;
  range_start: string | null;
  range_end: string | null;
  events_scanned: number;
  hits: number;
  alerts_created: number;
  alerts_updated: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

// ---------------------------------------------------------------- alerts

export type AlertStatus = 'new' | 'investigating' | 'true_positive' | 'false_positive' | 'closed';

export interface AlertSummary {
  id: number;
  rule_id: string | null;
  title: string;
  severity: Severity;
  status: AlertStatus;
  first_seen: string;
  last_seen: string;
  event_count: number;
  host_name: string | null;
  source_ip: string | null;
  user_name: string | null;
  mitre_tactics: string[];
  mitre_techniques: string[];
  case_id: number | null;
  assignee_id: number | null;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AlertPage {
  items: AlertSummary[];
  total: number;
}

export interface AlertDetail extends AlertSummary {
  /** Empty until the alert has been enriched. */
  enrichment: AlertEnrichment | Record<string, never>;
  rule: { id: string; title: string; description: string; false_positives: string[] } | null;
  evidence: EventRecord[];
  activity: Activity[];
}

/** One audit entry about an alert or a case. */
export interface Activity {
  id: number;
  occurred_at: string;
  username: string | null;
  action: string;
  details: Record<string, unknown>;
}

export interface BulkAlertResult {
  updated: number[];
  unchanged: number[];
  missing: number[];
  conflicts: { alert_id: number; open_alert_id: number }[];
}

export interface TimelineEvent extends EventRecord {
  is_evidence: boolean;
}

export interface AlertTimeline {
  start: string;
  end: string;
  window_minutes: number;
  entities: Record<string, string>;
  truncated: boolean;
  events: TimelineEvent[];
}

// ---------------------------------------------------------------- threat intel

export type IocType = 'ip' | 'domain' | 'md5' | 'sha1' | 'sha256';
export type Verdict = 'unknown' | 'clean' | 'suspicious' | 'malicious';
export type LookupStatus = 'ok' | 'not_found' | 'error' | 'rate_limited';

export interface Ioc {
  id: number;
  ioc_type: IocType;
  value: string;
  source: string;
  description: string | null;
  confidence: number | null;
  tags: string[];
  is_active: boolean;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
  match_count: number;
  last_matched_at: string | null;
}

export interface IocPage {
  items: Ioc[];
  total: number;
}

export interface IocMatch {
  event_id: number;
  field: string;
  matched_at: string;
  timestamp: string;
  log_source: string;
  host_name: string | null;
  source_ip: string | null;
  user_name: string | null;
  event_action: string | null;
  message: string | null;
}

export interface IocDetail extends Ioc {
  matches: IocMatch[];
}

export interface IntelSummary {
  total: number;
  active: number;
  by_type: Partial<Record<IocType, number>>;
  matched_events: number;
  indicators_matched: number;
}

export interface FeedImportResult {
  filename: string;
  source: string;
  indicators: number;
  created: number;
  updated: number;
  duplicates: number;
  problem_count: number;
  problems: MalformedSample[];
  truncated: boolean;
  sweep_queued: boolean;
}

export interface ProviderLookup {
  provider: string;
  label: string;
  status: LookupStatus;
  verdict: Verdict;
  data: Record<string, unknown>;
  fetched_at: string | null;
  cached: boolean;
}

export interface LookupResult {
  ioc_type: IocType;
  value: string;
  verdict: Verdict;
  shared: boolean;
  online: boolean;
  intel: Ioc[];
  providers: ProviderLookup[];
}

export interface ProviderStatus {
  name: string;
  label: string;
  configured: boolean;
  cooling_down: boolean;
  remaining: Record<string, number>;
}

export interface ProvidersInfo {
  online: boolean;
  cache_hours: number;
  providers: ProviderStatus[];
}

/** A local indicator as summarised on an alert. */
export interface IntelHit {
  id: number;
  type: IocType;
  value: string;
  source: string;
  description: string | null;
  confidence: number | null;
  tags: string[];
}

export interface EnrichedIndicator {
  type: IocType;
  value: string;
  fields: string[];
  verdict: Verdict;
  /** Whether the indicator may be sent to online providers. */
  shared: boolean;
  intel: IntelHit[];
  providers: ProviderLookup[];
}

export interface AlertEnrichment {
  enriched_at: string;
  verdict: Verdict;
  pending: boolean;
  online: boolean;
  indicators: EnrichedIndicator[];
}

export interface EventIndicator {
  ioc_id: number;
  ioc_type: IocType;
  value: string;
  field: string;
  source: string;
  description: string | null;
  confidence: number | null;
  tags: string[];
  is_active: boolean;
}

// ---------------------------------------------------------------- users

export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface User {
  id: number;
  username: string;
  full_name: string | null;
  role: UserRole;
  is_active: boolean;
}

// ---------------------------------------------------------------- cases

export type CaseStatus = 'open' | 'in_progress' | 'resolved' | 'closed';

export interface CaseSummary {
  id: number;
  title: string;
  severity: Severity;
  status: CaseStatus;
  assignee_id: number | null;
  created_by_id: number | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  closed_at: string | null;
  alert_count: number;
  open_alert_count: number;
  note_count: number;
  evidence_count: number;
}

export interface CasePage {
  items: CaseSummary[];
  total: number;
}

export interface CaseNote {
  id: number;
  body: string;
  author: string | null;
  created_at: string;
}

export interface CaseEvidence {
  id: number;
  note: string | null;
  added_by: string | null;
  created_at: string;
  event: EventRecord;
}

export interface UserRef {
  id: number;
  username: string;
  full_name: string | null;
}

export interface CaseDetail extends CaseSummary {
  description: string;
  resolution: string | null;
  assignee: UserRef | null;
  created_by: UserRef | null;
  alerts: AlertSummary[];
  notes: CaseNote[];
  evidence: CaseEvidence[];
  activity: Activity[];
  tactics: string[];
  techniques: string[];
  entities: { hosts: string[]; ips: string[]; users: string[] };
}

// ---------------------------------------------------------------- investigation

export type EntityKind = 'ip' | 'user' | 'host';

export interface Counted {
  value: string;
  count: number;
}

export interface EntityProfile {
  kind: EntityKind;
  value: string;
  query: string;
  event_count: number;
  first_seen: string | null;
  last_seen: string | null;
  log_sources: Counted[];
  activity: { day: string; count: number }[];
  related: Partial<Record<'users' | 'hosts' | 'ips', Counted[]>>;
  alert_count: number;
  open_alert_count: number;
  alerts: AlertSummary[];
  cases: CaseSummary[];
  intel: Ioc[];
}

export interface TechniqueCell {
  id: string;
  name: string | null;
  rules: string[];
  enabled_rules: number;
  alerts: number;
  open_alerts: number;
  last_seen: string | null;
}

export interface AttackMatrix {
  tactics: { id: string; name: string; techniques: TechniqueCell[] }[];
  techniques_covered: number;
  techniques_detected: number;
}
