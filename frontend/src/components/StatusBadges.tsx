import type { AlertStatus, CaseStatus } from '../api/types';
import { alertStatusLabel, caseStatusLabel } from '../lib/labels';

export function AlertStatusBadge({ status }: { status: AlertStatus }) {
  return (
    <span className="pill" data-alert-status={status}>
      {alertStatusLabel(status)}
    </span>
  );
}

export function CaseStatusBadge({ status }: { status: CaseStatus }) {
  return (
    <span className="pill" data-case-status={status}>
      {caseStatusLabel(status)}
    </span>
  );
}
