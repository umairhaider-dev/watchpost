const BYTE_UNITS = ['KB', 'MB', 'GB', 'TB'] as const;

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${BYTE_UNITS[unit] ?? 'TB'}`;
}

export function formatNumber(value: number): string {
  return value.toLocaleString('en-US');
}

/** UTC timestamp in a fixed, sortable form: 2026-10-12 09:02:13 UTC. */
export function formatUtc(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return `${date.toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

/** Elapsed time between two ISO timestamps (or until ``now`` if not finished). */
export function formatDuration(
  startIso: string | null,
  endIso: string | null,
  now: number = Date.now(),
): string {
  if (!startIso) return '—';
  const end = endIso ? new Date(endIso).getTime() : now;
  const seconds = Math.max(0, (end - new Date(startIso).getTime()) / 1000);
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${minutes} m ${String(rest).padStart(2, '0')} s`;
}

/** Share of a job's file read so far, as a whole percentage. */
export function progressPercent(processed: number, total: number): number {
  if (total <= 0) return 0;
  return Math.min(100, Math.round((processed / total) * 100));
}
