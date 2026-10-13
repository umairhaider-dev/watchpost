import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiGet, apiSend } from './client';
import type {
  AlertDetail,
  AlertPage,
  AlertStatus,
  DetectionRun,
  EventPage,
  FieldInfo,
  HealthResponse,
  IngestInfo,
  IngestionJobDetail,
  IngestionJobPage,
  LogSource,
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
  events: (logSource: LogSource | '') => ['events', logSource] as const,
  rules: ['rules'] as const,
  rule: (id: string) => ['rules', id] as const,
  detectionRuns: ['detection', 'runs'] as const,
  alerts: (filters: AlertFilters) => ['alerts', filters] as const,
  alert: (id: number) => ['alerts', 'detail', id] as const,
};

export interface AlertFilters {
  severity: Severity[];
  status: AlertStatus | '';
  ruleId: string;
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

export function useEvents(logSource: LogSource | '') {
  return useInfiniteQuery({
    queryKey: queryKeys.events(logSource),
    queryFn: ({ signal, pageParam }) =>
      apiGet<EventPage>('/events', {
        signal,
        params: { limit: 100, log_source: logSource || undefined, cursor: pageParam },
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
    queryFn: ({ signal }) => {
      const params = new URLSearchParams({ limit: '100' });
      for (const severity of filters.severity) params.append('severity', severity);
      if (filters.status) params.set('status', filters.status);
      if (filters.ruleId) params.set('rule_id', filters.ruleId);
      return apiGet<AlertPage>(`/alerts?${params.toString()}`, { signal });
    },
    refetchInterval: IDLE_POLL_MS,
  });
}

export function useAlert(id: number) {
  return useQuery({
    queryKey: queryKeys.alert(id),
    queryFn: ({ signal }) => apiGet<AlertDetail>(`/alerts/${String(id)}`, { signal }),
  });
}
