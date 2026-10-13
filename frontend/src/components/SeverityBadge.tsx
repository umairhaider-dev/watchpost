import type { Severity } from '../api/types';

const LABELS: Record<Severity, string> = {
  informational: 'Info',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className="severity" data-severity={severity}>
      {LABELS[severity]}
    </span>
  );
}
