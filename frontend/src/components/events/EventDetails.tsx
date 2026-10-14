import { useEventIndicators } from '../../api/queries';
import type { EventRecord } from '../../api/types';
import { formatUtc } from '../../lib/format';
import { IOC_TYPE_LABELS } from '../../lib/intel';
import { PinEvidenceForm } from '../cases/PinEvidenceForm';

function EventIndicators({ id }: { id: number }) {
  const indicators = useEventIndicators(id);
  if (indicators.isPending) return <p className="muted small">Loading matched indicators…</p>;
  if (indicators.isError) return <p className="text-error small">Could not load indicators.</p>;
  return (
    <ul className="context-list">
      {indicators.data.map((indicator) => (
        <li key={`${String(indicator.ioc_id)}:${indicator.field}`}>
          <span className="mono indicator__value">{indicator.value}</span>
          <span className="badge">{IOC_TYPE_LABELS[indicator.ioc_type]}</span>
          <span className="muted small">
            in {indicator.field} · {indicator.source}
            {indicator.confidence !== null ? ` · confidence ${String(indicator.confidence)}` : ''}
          </span>
          {indicator.description ? <span className="small">{indicator.description}</span> : null}
        </li>
      ))}
    </ul>
  );
}

/** Extra fields, threat intel matches and the original record of an event. */
export function EventDetails({ event }: { event: EventRecord }) {
  const extras: [string, string | number | null][] = [
    ['Event ID', event.id],
    ['Event code', event.event_code],
    ['Category', event.event_category],
    ['Process', event.process_name],
    ['Parent process', event.process_parent_name],
    [
      'Destination',
      event.destination_ip
        ? `${event.destination_ip}:${String(event.destination_port ?? '')}`
        : null,
    ],
    ['User agent', event.user_agent],
    ['Ingested', formatUtc(event.ingested_at)],
  ];

  return (
    <div className="event-details">
      {event.ioc_matched ? (
        <>
          <h3 className="subheading">Threat intel matches</h3>
          <EventIndicators id={event.id} />
        </>
      ) : null}
      <dl className="facts facts--inline">
        {extras
          .filter(
            (entry): entry is [string, string | number] => entry[1] !== null && entry[1] !== '',
          )
          .map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd className="mono">{value}</dd>
            </div>
          ))}
      </dl>
      <PinEvidenceForm eventId={event.id} />
      <h3 className="subheading">Raw event</h3>
      <pre className="code">{JSON.stringify(event.raw_event, null, 2)}</pre>
    </div>
  );
}
