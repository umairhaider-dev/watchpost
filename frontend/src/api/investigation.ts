import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { rangeStart, type TimeRange } from '../lib/time';
import { apiGet, apiSend } from './client';
import type {
  AlertStatus,
  AlertSummary,
  AlertTimeline,
  AttackMatrix,
  BulkAlertResult,
  CaseDetail,
  CaseEvidence,
  CaseNote,
  CasePage,
  CaseStatus,
  EntityKind,
  EntityProfile,
  Severity,
  User,
} from './types';

const investigationKeys = {
  users: ['users', 'assignable'] as const,
  timeline: (id: number, windowMinutes: number) =>
    ['alerts', 'timeline', id, windowMinutes] as const,
  cases: ['cases'] as const,
  caseList: (filters: CaseFilters) => ['cases', 'list', filters] as const,
  case: (id: number) => ['cases', 'detail', id] as const,
  entity: (kind: EntityKind, value: string) => ['entities', kind, value] as const,
  matrix: (range: TimeRange) => ['mitre', 'matrix', range] as const,
};

// ---------------------------------------------------------------- users

/** Analysts and admins who can own alerts and cases. */
export function useAssignableUsers() {
  return useQuery({
    queryKey: investigationKeys.users,
    queryFn: ({ signal }) => apiGet<User[]>('/users', { signal, params: { assignable: 'true' } }),
    staleTime: 60_000,
  });
}

// ---------------------------------------------------------------- alert triage

export interface AlertChanges {
  status?: AlertStatus;
  /** null unassigns. */
  assignee_id?: number | null;
}

export function useUpdateAlert(id: number) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (changes: AlertChanges) =>
      apiSend<AlertSummary>('PATCH', `/alerts/${String(id)}`, changes),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
}

export function useBulkUpdateAlerts() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (payload: AlertChanges & { alert_ids: number[] }) =>
      apiSend<BulkAlertResult>('POST', '/alerts/bulk', payload),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
}

export function useAlertTimeline(id: number, windowMinutes: number) {
  return useQuery({
    queryKey: investigationKeys.timeline(id, windowMinutes),
    queryFn: ({ signal }) =>
      apiGet<AlertTimeline>(`/alerts/${String(id)}/timeline`, {
        signal,
        params: { window_minutes: windowMinutes },
      }),
  });
}

// ---------------------------------------------------------------- cases

export interface CaseFilters {
  status: CaseStatus | '' | 'active';
  assignee: string;
  q: string;
}

export function useCases(filters: CaseFilters) {
  return useQuery({
    queryKey: investigationKeys.caseList(filters),
    queryFn: ({ signal }) => {
      const params = new URLSearchParams({ limit: '100' });
      if (filters.status === 'active') {
        params.append('status', 'open');
        params.append('status', 'in_progress');
      } else if (filters.status) {
        params.set('status', filters.status);
      }
      if (filters.assignee === 'none') params.set('unassigned', 'true');
      else if (filters.assignee) params.set('assignee_id', filters.assignee);
      if (filters.q.trim()) params.set('q', filters.q.trim());
      return apiGet<CasePage>(`/cases?${params.toString()}`, { signal });
    },
  });
}

export function useCase(id: number, enabled = true) {
  return useQuery({
    queryKey: investigationKeys.case(id),
    queryFn: ({ signal }) => apiGet<CaseDetail>(`/cases/${String(id)}`, { signal }),
    enabled,
  });
}

export interface NewCase {
  title: string;
  description?: string;
  severity?: Severity;
  assignee_id?: number;
  alert_ids?: number[];
}

/** Everything a case change can affect: case lists, the case itself and its alerts. */
function useInvalidateCases() {
  const client = useQueryClient();
  return async () => {
    await client.invalidateQueries({ queryKey: investigationKeys.cases });
    await client.invalidateQueries({ queryKey: ['alerts'] });
  };
}

export function useCreateCase() {
  const invalidate = useInvalidateCases();
  return useMutation({
    mutationFn: (payload: NewCase) => apiSend<CaseDetail>('POST', '/cases', payload),
    onSuccess: invalidate,
  });
}

export interface CaseChanges {
  title?: string;
  description?: string;
  severity?: Severity;
  status?: CaseStatus;
  assignee_id?: number | null;
  resolution?: string | null;
}

export function useUpdateCase(id: number) {
  const client = useQueryClient();
  const invalidate = useInvalidateCases();
  return useMutation({
    mutationFn: (changes: CaseChanges) =>
      apiSend<CaseDetail>('PATCH', `/cases/${String(id)}`, changes),
    onSuccess: async (detail) => {
      client.setQueryData(investigationKeys.case(id), detail);
      await invalidate();
    },
  });
}

export function useLinkAlerts() {
  const invalidate = useInvalidateCases();
  return useMutation({
    mutationFn: ({ caseId, alertIds }: { caseId: number; alertIds: number[] }) =>
      apiSend<{ added: number[] }>('POST', `/cases/${String(caseId)}/alerts`, {
        alert_ids: alertIds,
      }),
    onSuccess: invalidate,
  });
}

export function useUnlinkAlert(caseId: number) {
  const invalidate = useInvalidateCases();
  return useMutation({
    mutationFn: (alertId: number) =>
      apiSend<undefined>('DELETE', `/cases/${String(caseId)}/alerts/${String(alertId)}`),
    onSuccess: invalidate,
  });
}

export function useAddNote(caseId: number) {
  const invalidate = useInvalidateCases();
  return useMutation({
    mutationFn: (body: string) =>
      apiSend<CaseNote>('POST', `/cases/${String(caseId)}/notes`, { body }),
    onSuccess: invalidate,
  });
}

export function usePinEvidence() {
  const invalidate = useInvalidateCases();
  return useMutation({
    mutationFn: ({ caseId, eventId, note }: { caseId: number; eventId: number; note: string }) =>
      apiSend<CaseEvidence>('POST', `/cases/${String(caseId)}/evidence`, {
        event_id: eventId,
        note: note.trim() || null,
      }),
    onSuccess: invalidate,
  });
}

export function useUnpinEvidence(caseId: number) {
  const invalidate = useInvalidateCases();
  return useMutation({
    mutationFn: (evidenceId: number) =>
      apiSend<undefined>('DELETE', `/cases/${String(caseId)}/evidence/${String(evidenceId)}`),
    onSuccess: invalidate,
  });
}

export function caseReportUrl(caseId: number, format: 'markdown' | 'pdf'): string {
  return `/api/cases/${String(caseId)}/report?format=${format}`;
}

// ---------------------------------------------------------------- entities and ATT&CK

export function useEntity(kind: EntityKind, value: string) {
  return useQuery({
    queryKey: investigationKeys.entity(kind, value),
    queryFn: ({ signal }) =>
      apiGet<EntityProfile>(`/entities/${kind}`, { signal, params: { value } }),
    enabled: value.trim() !== '',
  });
}

export function useAttackMatrix(range: TimeRange) {
  return useQuery({
    queryKey: investigationKeys.matrix(range),
    queryFn: ({ signal }) =>
      apiGet<AttackMatrix>('/mitre/matrix', { signal, params: { since: rangeStart(range) } }),
  });
}
