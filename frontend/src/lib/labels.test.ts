import { describe, expect, it } from 'vitest';

import type { Activity } from '../api/types';
import { describeActivity } from './labels';
import { isTimeRange, rangeStart } from './time';

function entry(action: string, details: Record<string, unknown> = {}): Activity {
  return { id: 1, occurred_at: '2026-10-12T09:00:00Z', username: null, action, details };
}

describe('describeActivity', () => {
  it.each([
    [
      entry('alert.status_changed', { from: 'new', to: 'true_positive' }),
      'changed the status from new to true positive',
    ],
    [
      entry('case.status_changed', { from: 'in_progress', to: 'closed' }),
      'changed the status from in progress to closed',
    ],
    [entry('case.assigned', { assignee: 'analyst.one' }), 'assigned it to analyst.one'],
    [entry('alert.assigned', { assignee: null }), 'unassigned it'],
    [entry('case.created'), 'opened the case'],
    [entry('case.alerts_added', { alert_ids: [4, 5] }), 'added alerts #4, #5'],
    [entry('case.alert_removed', { alert_id: 4 }), 'removed alert #4'],
    [entry('case.alert_removed', { alert_id: 4, moved_to: 9 }), 'moved alert #4 to case #9'],
    [entry('case.note_added'), 'added a note'],
    [entry('case.evidence_added', { event_id: 12 }), 'pinned event #12 as evidence'],
    [entry('case.evidence_removed', { event_id: 12 }), 'unpinned event #12'],
    [entry('case.updated', { fields: ['severity', 'title'] }), 'edited the severity, title'],
    [entry('case.updated'), 'edited the details'],
    [entry('case.archived'), 'case.archived'],
  ])('describes %o', (activity, expected) => {
    expect(describeActivity(activity)).toBe(expected);
  });
});

describe('time ranges', () => {
  it('turns a range into a start time', () => {
    const now = Date.parse('2026-10-12T12:00:00Z');
    expect(rangeStart('1h', now)).toBe('2026-10-12T11:00:00.000Z');
    expect(rangeStart('7d', now)).toBe('2026-10-05T12:00:00.000Z');
    expect(rangeStart('all', now)).toBeUndefined();
  });

  it('recognises valid ranges', () => {
    expect(isTimeRange('24h')).toBe(true);
    expect(isTimeRange('2y')).toBe(false);
    expect(isTimeRange(null)).toBe(false);
  });
});
