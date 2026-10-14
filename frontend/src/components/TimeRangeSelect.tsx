import { useId } from 'react';

import { TIME_RANGES, type TimeRange } from '../lib/time';

interface TimeRangeSelectProps {
  value: TimeRange;
  label?: string;
  onChange: (range: TimeRange) => void;
}

export function TimeRangeSelect({ value, label = 'Time range', onChange }: TimeRangeSelectProps) {
  const id = useId();
  return (
    <div className="inline-field">
      <label htmlFor={id} className="muted small">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => {
          onChange(event.target.value as TimeRange);
        }}
      >
        {TIME_RANGES.map((range) => (
          <option key={range.value} value={range.value}>
            {range.label}
          </option>
        ))}
      </select>
    </div>
  );
}
