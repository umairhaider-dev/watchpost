import type { ReactNode } from 'react';

import { formatNumber } from '../../lib/format';

export interface BarItem {
  key: string;
  label: ReactNode;
  value: number;
  detail?: ReactNode;
  /** Colour of the bar (data-tone), e.g. a severity. */
  tone?: string;
}

interface BarListProps {
  items: BarItem[];
  label: string;
  emptyText: string;
}

/** A ranked list with a proportional bar under each entry. */
export function BarList({ items, label, emptyText }: BarListProps) {
  if (items.length === 0) return <p className="muted small">{emptyText}</p>;
  const peak = Math.max(1, ...items.map((item) => item.value));
  return (
    <ul className="bar-list" aria-label={label}>
      {items.map((item) => (
        <li key={item.key}>
          <div className="bar-list__row">
            <span className="bar-list__label">{item.label}</span>
            <span className="bar-list__value">{formatNumber(item.value)}</span>
          </div>
          <div className="bar-list__track" aria-hidden="true">
            <span
              className="bar-list__fill"
              data-tone={item.tone}
              style={{ width: `${String((item.value / peak) * 100)}%` }}
            />
          </div>
          {item.detail ? <span className="muted small">{item.detail}</span> : null}
        </li>
      ))}
    </ul>
  );
}
