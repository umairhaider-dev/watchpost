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
