import type { Verdict } from '../../api/types';

const LABELS: Record<Verdict, string> = {
  unknown: 'Unknown',
  clean: 'Clean',
  suspicious: 'Suspicious',
  malicious: 'Malicious',
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className="verdict" data-verdict={verdict}>
      {LABELS[verdict]}
    </span>
  );
}
