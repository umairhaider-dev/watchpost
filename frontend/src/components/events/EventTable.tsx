import { Fragment, type ReactNode, useState } from 'react';

import type { EventRecord } from '../../api/types';
import { formatUtc } from '../../lib/format';
import { EntityLink } from '../EntityLink';
import { eventSummary } from '../../lib/events';
import { EventDetails } from './EventDetails';

const COLUMN_COUNT = 7;

interface EventTableProps<T extends EventRecord> {
  events: T[];
  /** Extra marker shown next to the time, e.g. "evidence". */
  marker?: (event: T) => ReactNode;
  rowClass?: (event: T) => string | undefined;
}

/** Events with links to their entities; a row expands to show the full record. */
export function EventTable<T extends EventRecord>({
  events,
  marker,
  rowClass,
}: EventTableProps<T>) {
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Source</th>
            <th scope="col">Host</th>
            <th scope="col">User</th>
            <th scope="col">Source IP</th>
            <th scope="col">Action</th>
            <th scope="col">Details</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => {
            const isOpen = expanded === event.id;
            const classes = [isOpen ? 'is-open' : '', rowClass?.(event) ?? '']
              .filter(Boolean)
              .join(' ');
            return (
              <Fragment key={event.id}>
                <tr className={classes || undefined}>
                  <td className="nowrap">
                    <button
                      type="button"
                      className="row-toggle"
                      aria-expanded={isOpen}
                      onClick={() => {
                        setExpanded(isOpen ? null : event.id);
                      }}
                    >
                      <span className="row-toggle__chevron" aria-hidden="true" />
                      <span className="mono">{formatUtc(event.timestamp)}</span>
                    </button>
                    {marker?.(event)}
                  </td>
                  <td className="nowrap">
                    <span className="badge">{event.log_source}</span>
                    {event.ioc_matched ? (
                      <span className="ioc-flag" title="Matched a threat indicator">
                        IOC
                      </span>
                    ) : null}
                  </td>
                  <td>
                    <EntityLink kind="host" value={event.host_name} />
                  </td>
                  <td>
                    <EntityLink kind="user" value={event.user_name} />
                  </td>
                  <td>
                    <EntityLink kind="ip" value={event.source_ip} />
                  </td>
                  <td>
                    {event.event_action ? (
                      <span className="action" data-outcome={event.event_outcome ?? 'unknown'}>
                        {event.event_action}
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="excerpt">{eventSummary(event)}</td>
                </tr>
                {isOpen ? (
                  <tr className="row-details">
                    <td colSpan={COLUMN_COUNT}>
                      <EventDetails event={event} />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
