import type { Activity, AlertStatus, CaseStatus } from '../api/types';

export const ALERT_STATUSES: { value: AlertStatus; label: string }[] = [
  { value: 'new', label: 'New' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'true_positive', label: 'True positive' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'closed', label: 'Closed' },
];

export const CASE_STATUSES: { value: CaseStatus; label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'in_progress', label: 'In progress' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'closed', label: 'Closed' },
];

export function alertStatusLabel(status: AlertStatus): string {
  return ALERT_STATUSES.find((option) => option.value === status)?.label ?? status;
}

export function caseStatusLabel(status: CaseStatus): string {
  return CASE_STATUSES.find((option) => option.value === status)?.label ?? status;
}

function words(value: unknown): string {
  return typeof value === 'string' ? value.replaceAll('_', ' ') : String(value);
}

function idList(value: unknown): string {
  return Array.isArray(value) ? value.map((id) => `#${String(id)}`).join(', ') : '';
}

/** A readable sentence for one audit entry about an alert or a case. */
export function describeActivity(entry: Activity): string {
  const details = entry.details;
  switch (entry.action) {
    case 'alert.status_changed':
    case 'case.status_changed':
      return `changed the status from ${words(details.from)} to ${words(details.to)}`;
    case 'alert.assigned':
    case 'case.assigned':
      return typeof details.assignee === 'string'
        ? `assigned it to ${details.assignee}`
        : 'unassigned it';
    case 'case.created':
      return 'opened the case';
    case 'case.alerts_added':
      return `added alerts ${idList(details.alert_ids)}`;
    case 'case.alert_removed':
      return typeof details.moved_to === 'number'
        ? `moved alert #${String(details.alert_id)} to case #${String(details.moved_to)}`
        : `removed alert #${String(details.alert_id)}`;
    case 'case.note_added':
      return 'added a note';
    case 'case.evidence_added':
      return `pinned event #${String(details.event_id)} as evidence`;
    case 'case.evidence_removed':
      return `unpinned event #${String(details.event_id)}`;
    case 'case.updated':
      return `edited the ${Array.isArray(details.fields) ? details.fields.join(', ') : 'details'}`;
    default:
      return entry.action;
  }
}
