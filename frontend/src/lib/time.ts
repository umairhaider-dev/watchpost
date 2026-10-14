/** Relative time ranges shared by the alert queue, event search and ATT&CK matrix. */
export const TIME_RANGES = [
  { value: '15m', label: 'Last 15 minutes', minutes: 15 },
  { value: '1h', label: 'Last hour', minutes: 60 },
  { value: '24h', label: 'Last 24 hours', minutes: 60 * 24 },
  { value: '7d', label: 'Last 7 days', minutes: 60 * 24 * 7 },
  { value: '30d', label: 'Last 30 days', minutes: 60 * 24 * 30 },
  { value: 'all', label: 'All time', minutes: null },
] as const;

export type TimeRange = (typeof TIME_RANGES)[number]['value'];

export function isTimeRange(value: string | null): value is TimeRange {
  return TIME_RANGES.some((range) => range.value === value);
}

/** ISO start of a relative range, or undefined for "all time". */
export function rangeStart(range: TimeRange, now: number = Date.now()): string | undefined {
  const minutes = TIME_RANGES.find((option) => option.value === range)?.minutes ?? null;
  return minutes === null ? undefined : new Date(now - minutes * 60_000).toISOString();
}
