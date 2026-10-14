import type { EventRecord } from '../api/types';

/** The most telling single line of an event. */
export function eventSummary(event: EventRecord): string {
  if (event.process_command_line) return event.process_command_line;
  if (event.url_original) {
    return `${event.http_method ?? ''} ${event.url_original} ${String(event.http_status_code ?? '')}`.trim();
  }
  return event.message ?? '';
}
