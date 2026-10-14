import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { rangeStart, type TimeRange } from '../lib/time';
import { apiGet, apiPostForm, apiSend } from './client';
import type {
  AlertDetail,
  AlertEnrichment,
  AlertPage,
  AlertStatus,
  DetectionRun,
  EventIndicator,
  EventPage,
  FeedImportResult,
  FieldInfo,
  HealthResponse,
  IngestInfo,
  IngestionJobDetail,
  IngestionJobPage,
  IntelSummary,
  Ioc,
  IocDetail,
  IocPage,
  IocType,
  LogSource,
  LookupResult,
  ProvidersInfo,
  ReadinessResponse,
  RuleDetail,
  RuleSummary,
  RuleTestResult,
  RuleValidation,
  Severity,
} from './types';

export const queryKeys = {
  health: ['health'] as const,
  readiness: ['health', 'ready'] as const,
  fields: ['meta', 'fields'] as const,
  ingestInfo: ['ingest', 'info'] as const,
  ingestJobs: ['ingest', 'jobs'] as const,
  ingestJob: (id: number) => ['ingest', 'jobs', id] as const,
  events: (search: EventSearch) => ['events', 'list', search] as const,
  eventIndicators: (id: number) => ['events', 'indicators', id] as const,
  rules: ['rules'] as const,
  rule: (id: string) => ['rules', id] as const,
  detectionRuns: ['detection', 'runs'] as const,
  alerts: (filters: AlertFilters) => ['alerts', filters] as const,
  alert: (id: number) => ['alerts', 'detail', id] as const,
  intel: ['intel'] as const,
  intelSummary: ['intel', 'summary'] as const,
  iocs: (filters: IocFilters) => ['intel', 'iocs', filters] as const,
  ioc: (id: number) => ['intel', 'iocs', 'detail', id] as const,
  providers: ['intel', 'providers'] as const,
};

export interface IocFilters {
  q: string;
  iocType: IocType | '';
  matchedOnly: boolean;
}

export type AlertSort = 'last_seen' | 'first_seen' | 'severity';

export interface AlertFilters {
  severity: Severity[];
  status: AlertStatus[];
  ruleId: string;
  host: string;
  sourceIp: string;
  user: string;
  technique: string;
  /** '' for anyone, 'none' for unassigned, otherwise a user ID. */
  assignee: string;
  range: TimeRange;
  sort: AlertSort;
}

export const DEFAULT_ALERT_FILTERS: AlertFilters = {
  severity: [],
  status: [],
  ruleId: '',
  host: '',
  sourceIp: '',
  user: '',
  technique: '',
  assignee: '',
  range: 'all',
  sort: 'last_seen',
};

export interface EventSearch {
  q: string;
  range: TimeRange;
  logSource: LogSource | '';
  iocOnly: boolean;
}

/** Query string for the alert list API. */
function alertParams(filters: AlertFilters, now: number = Date.now()): URLSearchParams {
  const params = new URLSearchParams({ limit: '100', sort: filters.sort });
  for (const severity of filters.severity) params.append('severity', severity);
  for (const status of filters.status) params.append('status', status);
  const text: [string, string][] = [
    ['rule_id', filters.ruleId],
    ['host', filters.host],
    ['source_ip', filters.sourceIp],
    ['user', filters.user],
    ['technique', filters.technique],
  ];
  for (const [key, value] of text) {
    if (value.trim()) params.set(key, value.trim());
  }
  if (filters.assignee === 'none') params.set('unassigned', 'true');
  else if (filters.assignee) params.set('assignee_id', filters.assignee);
  const since = rangeStart(filters.range, now);
  if (since) params.set('since', since);
  return params;
}

const ACTIVE_POLL_MS = 2_000;
const IDLE_POLL_MS = 15_000;

export function useHealth() {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: ({ signal }) => apiGet<HealthResponse>('/health', { signal }),
    refetchInterval: 30_000,
  });
}

export function useReadiness() {
  return useQuery({
    queryKey: queryKeys.readiness,
    queryFn: ({ signal }) =>
      apiGet<ReadinessResponse>('/health/ready', { signal, acceptStatuses: [503] }),
    refetchInterval: 15_000,
  });
}

export function useEventFields() {
  return useQuery({
    queryKey: queryKeys.fields,
    queryFn: ({ signal }) => apiGet<FieldInfo[]>('/meta/fields', { signal }),
    staleTime: Infinity,
  });
}

export function useIngestInfo() {
  return useQuery({
    queryKey: queryKeys.ingestInfo,
    queryFn: ({ signal }) => apiGet<IngestInfo>('/ingest/info', { signal }),
    staleTime: Infinity,
  });
}

/** Recent ingestion jobs; polls quickly while any job is still in progress. */
export function useIngestionJobs() {
  return useQuery({
    queryKey: queryKeys.ingestJobs,
    queryFn: ({ signal }) =>
      apiGet<IngestionJobPage>('/ingest/jobs', { signal, params: { limit: 50 } }),
    refetchInterval: (query) => {
      const active = query.state.data?.items.some(
        (job) => job.status === 'queued' || job.status === 'running',
      );
      return active ? ACTIVE_POLL_MS : IDLE_POLL_MS;
    },
  });
}

export function useIngestionJob(id: number) {
  return useQuery({
    queryKey: queryKeys.ingestJob(id),
    queryFn: ({ signal }) => apiGet<IngestionJobDetail>(`/ingest/jobs/${String(id)}`, { signal }),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'queued' || status === 'running' ? ACTIVE_POLL_MS : false;
    },
  });
}

/** Event search, newest first, loaded a page at a time. */
export function useEventSearch(search: EventSearch) {
  return useInfiniteQuery({
    queryKey: queryKeys.events(search),
    queryFn: ({ signal, pageParam }) =>
      apiGet<EventPage>('/events', {
        signal,
        params: {
          limit: 100,
          q: search.q.trim() || undefined,
          start: rangeStart(search.range),
          log_source: search.logSource || undefined,
          ioc_matched: search.iocOnly ? 'true' : undefined,
          cursor: pageParam,
        },
      }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  });
}

// ---------------------------------------------------------------- rules

export function useRules() {
  return useQuery({
    queryKey: queryKeys.rules,
    queryFn: ({ signal }) => apiGet<RuleSummary[]>('/rules', { signal }),
  });
}

export function useRule(id: string) {
  return useQuery({
    queryKey: queryKeys.rule(id),
    queryFn: ({ signal }) => apiGet<RuleDetail>(`/rules/${id}`, { signal }),
  });
}

export function useToggleRule() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      apiSend<RuleDetail>('PATCH', `/rules/${id}`, { enabled }),
    onSuccess: async (rule) => {
      client.setQueryData(queryKeys.rule(rule.id), rule);
      await client.invalidateQueries({ queryKey: queryKeys.rules, exact: true });
    },
  });
}

export function useSaveRule(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (sourceYaml: string) =>
      apiSend<RuleDetail>('PUT', `/rules/${id}`, { source_yaml: sourceYaml }),
    onSuccess: async (rule) => {
      client.setQueryData(queryKeys.rule(rule.id), rule);
      await client.invalidateQueries({ queryKey: queryKeys.rules, exact: true });
    },
  });
}

export function useValidateRule() {
  return useMutation({
    mutationFn: (sourceYaml: string) =>
      apiSend<RuleValidation>('POST', '/rules/validate', { source_yaml: sourceYaml }),
  });
}

export interface RuleTestInput {
  sourceYaml: string;
  sample: string;
  parser: string;
}

export function useTestRule() {
  return useMutation({
    mutationFn: ({ sourceYaml, sample, parser }: RuleTestInput) =>
      apiSend<RuleTestResult>('POST', '/rules/test', { source_yaml: sourceYaml, sample, parser }),
  });
}

// ---------------------------------------------------------------- detection runs

export function useDetectionRuns() {
  return useQuery({
    queryKey: queryKeys.detectionRuns,
    queryFn: ({ signal }) =>
      apiGet<DetectionRun[]>('/detection/runs', { signal, params: { limit: 10 } }),
    refetchInterval: (query) => {
      const active = query.state.data?.some(
        (run) => run.status === 'queued' || run.status === 'running',
      );
      return active ? ACTIVE_POLL_MS : IDLE_POLL_MS;
    },
  });
}

export function useStartDetectionRun() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (range: { start?: string }) =>
      apiSend<DetectionRun>('POST', '/detection/runs', range),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: queryKeys.detectionRuns });
    },
  });
}

// ---------------------------------------------------------------- alerts

export function useAlerts(filters: AlertFilters) {
  return useQuery({
    queryKey: queryKeys.alerts(filters),
    queryFn: ({ signal }) =>
      apiGet<AlertPage>(`/alerts?${alertParams(filters).toString()}`, { signal }),
    refetchInterval: IDLE_POLL_MS,
  });
}

export function useAlert(id: number, enabled = true) {
  return useQuery({
    queryKey: queryKeys.alert(id),
    queryFn: ({ signal }) => apiGet<AlertDetail>(`/alerts/${String(id)}`, { signal }),
    enabled,
  });
}

/** Rebuild an alert's indicator context; ``refresh`` skips cached provider answers. */
export function useEnrichAlert(id: number) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (refresh: boolean) =>
      apiSend<AlertEnrichment>(
        'POST',
        `/alerts/${String(id)}/enrich${refresh ? '?refresh=true' : ''}`,
      ),
    onSuccess: (enrichment) => {
      client.setQueryData<AlertDetail>(queryKeys.alert(id), (current) =>
        current ? { ...current, enrichment } : current,
      );
    },
  });
}

export function useEventIndicators(id: number) {
  return useQuery({
    queryKey: queryKeys.eventIndicators(id),
    queryFn: ({ signal }) =>
      apiGet<EventIndicator[]>(`/events/${String(id)}/indicators`, { signal }),
  });
}

// ---------------------------------------------------------------- threat intel

export function useIntelSummary() {
  return useQuery({
    queryKey: queryKeys.intelSummary,
    queryFn: ({ signal }) => apiGet<IntelSummary>('/intel/summary', { signal }),
    refetchInterval: IDLE_POLL_MS,
  });
}

export function useIocs(filters: IocFilters) {
  return useQuery({
    queryKey: queryKeys.iocs(filters),
    queryFn: ({ signal }) =>
      apiGet<IocPage>('/intel/iocs', {
        signal,
        params: {
          limit: 100,
          q: filters.q.trim() || undefined,
          ioc_type: filters.iocType || undefined,
          matched: filters.matchedOnly ? 'true' : undefined,
        },
      }),
    // Sweeps after an import run in the background; match counts catch up.
    refetchInterval: IDLE_POLL_MS,
  });
}

export function useIoc(id: number) {
  return useQuery({
    queryKey: queryKeys.ioc(id),
    queryFn: ({ signal }) => apiGet<IocDetail>(`/intel/iocs/${String(id)}`, { signal }),
  });
}

export function useProviders() {
  return useQuery({
    queryKey: queryKeys.providers,
    queryFn: ({ signal }) => apiGet<ProvidersInfo>('/intel/providers', { signal }),
    refetchInterval: 60_000,
  });
}

function useInvalidateIntel() {
  const client = useQueryClient();
  return () => client.invalidateQueries({ queryKey: queryKeys.intel });
}

export interface NewIoc {
  value: string;
  ioc_type?: IocType;
  description?: string;
  confidence?: number;
  tags?: string[];
}

export function useAddIoc() {
  const invalidate = useInvalidateIntel();
  return useMutation({
    mutationFn: (ioc: NewIoc) => apiSend<Ioc>('POST', '/intel/iocs', ioc),
    onSuccess: invalidate,
  });
}

export function useUpdateIoc() {
  const invalidate = useInvalidateIntel();
  return useMutation({
    mutationFn: ({ id, ...changes }: { id: number; is_active?: boolean }) =>
      apiSend<Ioc>('PATCH', `/intel/iocs/${String(id)}`, changes),
    onSuccess: invalidate,
  });
}

export function useDeleteIoc() {
  const invalidate = useInvalidateIntel();
  return useMutation({
    mutationFn: (id: number) => apiSend<undefined>('DELETE', `/intel/iocs/${String(id)}`),
    onSuccess: invalidate,
  });
}

export interface FeedImportInput {
  file: File;
  source: string;
  confidence: string;
  tags: string;
  expiresInDays: string;
}

export function useImportFeed() {
  const invalidate = useInvalidateIntel();
  return useMutation({
    mutationFn: ({ file, source, confidence, tags, expiresInDays }: FeedImportInput) => {
      const form = new FormData();
      form.append('file', file);
      const optional = {
        source: source.trim(),
        confidence: confidence.trim(),
        tags: tags.trim(),
        expires_in_days: expiresInDays.trim(),
      };
      for (const [key, value] of Object.entries(optional)) {
        if (value) form.append(key, value);
      }
      return apiPostForm<FeedImportResult>('/intel/import', form);
    },
    onSuccess: invalidate,
  });
}

export function useSweepIndicators() {
  return useMutation({
    mutationFn: () => apiSend<{ queued: boolean }>('POST', '/intel/sweep'),
  });
}

export function useLookup() {
  return useMutation({
    mutationFn: ({ value, refresh }: { value: string; refresh: boolean }) =>
      apiGet<LookupResult>('/intel/lookup', {
        params: { value, refresh: refresh ? 'true' : undefined },
      }),
  });
}
