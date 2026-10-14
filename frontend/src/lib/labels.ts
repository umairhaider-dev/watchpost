import type { Activity, AlertStatus, CaseStatus, UserRole } from '../api/types';

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

// ---------------------------------------------------------------- roles

export const ROLES: { value: UserRole; label: string; description: string }[] = [
  {
    value: 'viewer',
    label: 'Viewer',
    description: 'Can look at alerts, cases, events, rules and intel, but not change anything.',
  },
  {
    value: 'analyst',
    label: 'Analyst',
    description:
      'Triages alerts, works cases, uploads logs, runs detection and manages threat intel.',
  },
  {
    value: 'admin',
    label: 'Admin',
    description:
      'Everything an analyst can do, plus editing rules, managing users and reading the audit log.',
  },
];

export function roleLabel(role: UserRole): string {
  return ROLES.find((option) => option.value === role)?.label ?? role;
}

// ---------------------------------------------------------------- audit log

/** Filter choices for the audit log; each value is an action prefix. */
export const AUDIT_AREAS: { value: string; label: string }[] = [
  { value: 'auth.', label: 'Sign-in' },
  { value: 'user.', label: 'User accounts' },
  { value: 'alert.', label: 'Alerts' },
  { value: 'case.', label: 'Cases' },
  { value: 'rule.', label: 'Rules' },
  { value: 'detection.', label: 'Detection runs' },
  { value: 'ingest.', label: 'Log uploads' },
  { value: 'intel.', label: 'Threat intel' },
];

const AUDIT_ACTIONS: Record<string, string> = {
  'auth.login': 'Signed in',
  'auth.login_failed': 'Failed sign-in',
  'auth.login_blocked': 'Sign-in blocked',
  'auth.logout': 'Signed out',
  'auth.password_changed': 'Changed own password',
  'user.created': 'Created a user',
  'user.updated': 'Changed a user',
  'user.password_reset': 'Reset a password',
  'alert.status_changed': 'Changed alert status',
  'alert.assigned': 'Assigned an alert',
  'alert.enrichment_requested': 'Requested enrichment',
  'case.created': 'Opened a case',
  'case.updated': 'Edited a case',
  'case.status_changed': 'Changed case status',
  'case.assigned': 'Assigned a case',
  'case.alerts_added': 'Added alerts to a case',
  'case.alert_removed': 'Removed an alert from a case',
  'case.note_added': 'Added a note',
  'case.evidence_added': 'Pinned evidence',
  'case.evidence_removed': 'Unpinned evidence',
  'rule.created': 'Created a rule',
  'rule.updated': 'Edited a rule',
  'rule.enabled': 'Enabled a rule',
  'rule.disabled': 'Disabled a rule',
  'rule.deleted': 'Deleted a rule',
  'detection.run_started': 'Started a detection run',
  'ingest.uploaded': 'Uploaded a log file',
  'intel.ioc_added': 'Added an indicator',
  'intel.ioc_updated': 'Edited an indicator',
  'intel.ioc_deleted': 'Deleted an indicator',
  'intel.feed_imported': 'Imported a feed',
  'intel.sweep_requested': 'Started an indicator sweep',
};

/** A short label for an audit action; unknown actions are shown as they are. */
export function auditActionLabel(action: string): string {
  return AUDIT_ACTIONS[action] ?? action;
}

/** Whether an audit entry records a refused attempt. */
export function isRefusal(action: string): boolean {
  return action === 'auth.login_failed' || action === 'auth.login_blocked';
}

function isChange(value: unknown): value is { from: unknown; to: unknown } {
  return typeof value === 'object' && value !== null && 'from' in value && 'to' in value;
}

function detailValue(value: unknown): string {
  if (isChange(value)) return `${detailValue(value.from)} → ${detailValue(value.to)}`;
  if (Array.isArray(value)) return value.map(detailValue).join(', ');
  // Strings are shown verbatim: file names and user names may contain underscores.
  if (typeof value === 'string') return value || 'none';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value === null || value === undefined) return 'none';
  return JSON.stringify(value);
}

/** ``details`` of an audit entry as "key: value" pairs, e.g. "role: analyst → admin". */
export function formatAuditDetails(details: Record<string, unknown>): string {
  return Object.entries(details)
    .map(([key, value]) => `${key.replaceAll('_', ' ')}: ${detailValue(value)}`)
    .join(' · ');
}
