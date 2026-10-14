import { formatBucket, formatNumber } from '../../lib/format';

export interface ColumnSegment {
  key: string;
  label: string;
  value: number;
  /** CSS class that colours the segment. */
  className: string;
}

export interface Column {
  start: string;
  segments: ColumnSegment[];
}

interface ColumnChartProps {
  columns: Column[];
  bucketSeconds: number;
  /** What the chart shows, for screen readers, e.g. "Alerts over time". */
  label: string;
  unit: string;
  emptyText: string;
}

const SLOT = 10;
const BAR = 8;
const TOP_MARGIN = 4;

function columnTotal(column: Column): number {
  return column.segments.reduce((sum, segment) => sum + segment.value, 0);
}

/** Stacked columns over time, drawn as a scalable SVG with a tooltip per column. */
export function ColumnChart({ columns, bucketSeconds, label, unit, emptyText }: ColumnChartProps) {
  const totals = columns.map(columnTotal);
  const peak = Math.max(1, ...totals);
  const sum = totals.reduce((acc, value) => acc + value, 0);
  const first = columns[0];
  const last = columns.at(-1);

  return (
    <figure className="chart">
      <svg
        className="chart__plot"
        viewBox={`0 0 ${String(Math.max(columns.length, 1) * SLOT)} 100`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${label}: ${formatNumber(sum)} ${unit} in ${String(columns.length)} intervals, at most ${formatNumber(Math.max(...totals, 0))} in one`}
      >
        <line className="chart__baseline" x1="0" x2={columns.length * SLOT} y1="100" y2="100" />
        {columns.map((column, index) => {
          let top = 100;
          const parts = column.segments.filter((segment) => segment.value > 0);
          const tooltip = parts.length
            ? parts.map((segment) => `${String(segment.value)} ${segment.label}`).join(', ')
            : `no ${unit}`;
          return (
            <g key={column.start} className="chart__column">
              <title>{`${formatBucket(column.start, bucketSeconds)}: ${tooltip}`}</title>
              <rect className="chart__hit" x={index * SLOT} y="0" width={SLOT} height="100" />
              {parts.map((segment) => {
                const height = (segment.value / peak) * (100 - TOP_MARGIN);
                top -= height;
                return (
                  <rect
                    key={segment.key}
                    className={segment.className}
                    x={index * SLOT + (SLOT - BAR) / 2}
                    y={top}
                    width={BAR}
                    height={height}
                  />
                );
              })}
            </g>
          );
        })}
      </svg>
      {sum === 0 ? <p className="chart__empty muted small">{emptyText}</p> : null}
      {first && last ? (
        <figcaption className="chart__axis small muted">
          <span>{formatBucket(first.start, bucketSeconds)}</span>
          <span>peak {formatNumber(Math.max(...totals))}</span>
          <span>{formatBucket(last.start, bucketSeconds)}</span>
        </figcaption>
      ) : null}
    </figure>
  );
}
