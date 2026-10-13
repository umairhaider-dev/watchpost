export type StatusTone = 'ok' | 'warn' | 'error' | 'unknown';

interface StatusIndicatorProps {
  tone: StatusTone;
  label: string;
}

export function StatusIndicator({ tone, label }: StatusIndicatorProps) {
  return (
    <span className="status" data-tone={tone}>
      <span className="status__dot" aria-hidden="true" />
      {label}
    </span>
  );
}
