import { useInfiniteQuery, useQuery } from '@tanstack/react-query';

import { apiGet } from './client';
import type {
  EventPage,
  FieldInfo,
  HealthResponse,
  IngestInfo,
  IngestionJobDetail,
  IngestionJobPage,
  LogSource,
  ReadinessResponse,
} from './types';

export const queryKeys = {
  health: ['health'] as const,
  readiness: ['health', 'ready'] as const,
  fields: ['meta', 'fields'] as const,
  ingestInfo: ['ingest', 'info'] as const,
  ingestJobs: ['ingest', 'jobs'] as const,
  ingestJob: (id: number) => ['ingest', 'jobs', id] as const,
  events: (logSource: LogSource | '') => ['events', logSource] as const,
};

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
