import { type SubmitEvent, useId, useState } from 'react';
import { Link } from 'react-router';

import { usePermissions } from '../../api/auth';
import { useCases, usePinEvidence } from '../../api/investigation';

/** Pin one event to an open case as evidence, with a note on why it matters. */
export function PinEvidenceForm({ eventId }: { eventId: number }) {
  const cases = useCases({ status: 'active', assignee: '', q: '' });
  const pin = usePinEvidence();
  const { canEdit } = usePermissions();
  const [caseId, setCaseId] = useState('');
  const [note, setNote] = useState('');
  const caseFieldId = useId();
  const noteId = useId();
  const openCases = cases.data?.items ?? [];

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!caseId) return;
    pin.mutate({ caseId: Number(caseId), eventId, note });
  }

  if (cases.isSuccess && openCases.length === 0) {
    return (
      <p className="muted small">
        Open a <Link to="/cases">case</Link> to pin this event as evidence.
      </p>
    );
  }

  if (!canEdit) return null;

  return (
    <form className="inline-form" onSubmit={handleSubmit} aria-label="Pin as evidence">
      <div className="inline-field">
        <label htmlFor={caseFieldId} className="muted small">
          Case
        </label>
        <select
          id={caseFieldId}
          value={caseId}
          onChange={(event) => {
            setCaseId(event.target.value);
            pin.reset();
          }}
        >
          <option value="">Choose a case…</option>
          {openCases.map((item) => (
            <option key={item.id} value={item.id}>
              #{item.id} {item.title}
            </option>
          ))}
        </select>
      </div>
      <div className="inline-field grow">
        <label htmlFor={noteId} className="muted small">
          Note
        </label>
        <input
          id={noteId}
          type="text"
          className="grow"
          maxLength={2000}
          placeholder="Why this event matters"
          value={note}
          onChange={(event) => {
            setNote(event.target.value);
          }}
        />
      </div>
      <button
        type="submit"
        className="button button--small button--secondary"
        disabled={!caseId || pin.isPending}
      >
        Pin as evidence
      </button>
      {pin.isSuccess ? (
        <span className="text-ok small" role="status">
          Pinned to <Link to={`/cases/${caseId}`}>case #{caseId}</Link>.
        </span>
      ) : null}
      {pin.isError ? (
        <span className="text-error small" role="alert">
          {pin.error.message}
        </span>
      ) : null}
    </form>
  );
}
