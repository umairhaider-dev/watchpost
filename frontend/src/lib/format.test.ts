import { describe, expect, it } from 'vitest';

import {
  formatBucket,
  formatBytes,
  formatDuration,
  formatNumber,
  formatSeconds,
  formatUtc,
  progressPercent,
} from './format';

describe('formatBytes', () => {
  it.each([
    [0, '0 B'],
    [1023, '1023 B'],
    [1536, '1.5 KB'],
    [512 * 1024 * 1024, '512 MB'],
    [3 * 1024 ** 3, '3.0 GB'],
    [5 * 1024 ** 5, '5120 TB'],
  ])('%d bytes -> %s', (bytes, expected) => {
    expect(formatBytes(bytes)).toBe(expected);
  });
});

describe('formatDuration', () => {
  const start = '2026-10-12T09:00:00Z';

  it('returns a dash before the job starts', () => {
    expect(formatDuration(null, null)).toBe('—');
  });

  it('formats short and long durations', () => {
    expect(formatDuration(start, '2026-10-12T09:00:01.250Z')).toBe('1.3 s');
    expect(formatDuration(start, '2026-10-12T09:00:42Z')).toBe('42 s');
    expect(formatDuration(start, '2026-10-12T09:03:05Z')).toBe('3 m 05 s');
  });

  it('measures running jobs against now', () => {
    expect(formatDuration(start, null, Date.parse('2026-10-12T09:00:30Z'))).toBe('30 s');
  });
});

describe('other formatters', () => {
  it('formats UTC timestamps', () => {
    expect(formatUtc('2026-10-12T11:02:13+02:00')).toBe('2026-10-12 09:02:13 UTC');
    expect(formatUtc('not a date')).toBe('not a date');
  });

  it('formats numbers and progress', () => {
    expect(formatNumber(1234567)).toBe('1,234,567');
    expect(progressPercent(50, 200)).toBe(25);
    expect(progressPercent(300, 200)).toBe(100);
    expect(progressPercent(10, 0)).toBe(0);
  });
});

describe('formatSeconds', () => {
  it.each([
    [null, '—'],
    [45.4, '45 s'],
    [720, '12 min'],
    [12_600, '3.5 h'],
    [181_440, '2.1 d'],
  ])('formats %s', (seconds, expected) => {
    expect(formatSeconds(seconds)).toBe(expected);
  });
});

describe('formatBucket', () => {
  it('shows the hour for sub-day buckets and the date otherwise', () => {
    expect(formatBucket('2026-10-12T09:00:00Z', 3600)).toBe('10-12 09:00');
    expect(formatBucket('2026-10-12T00:00:00Z', 86_400)).toBe('2026-10-12');
  });
});
