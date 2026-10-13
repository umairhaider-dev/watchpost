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
  trigger: 'ingestion' | 'manual';
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
  created_at: string;
  updated_at: string;
}

export interface AlertPage {
  items: AlertSummary[];
  total: number;
}

export interface AlertDetail extends AlertSummary {
  enrichment: Record<string, unknown>;
  rule: { id: string; title: string; description: string; false_positives: string[] } | null;
  evidence: EventRecord[];
}
