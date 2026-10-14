import { type SubmitEvent, useId, useState } from 'react';
import { Link } from 'react-router';

import { useCases, useCreateCase, useLinkAlerts } from '../../api/investigation';

interface AddToCaseFormProps {
  alertIds: number[];
  /** Suggested title when opening a new case. */
  defaultTitle?: string;
  onDone?: (caseId: number) => void;
}

const NEW_CASE = 'new';

/** Put alerts into an open case, or open a new case around them. */
export function AddToCaseForm({ alertIds, defaultTitle = '', onDone }: AddToCaseFormProps) {
  const cases = useCases({ status: 'active', assignee: '', q: '' });
  const link = useLinkAlerts();
  const create = useCreateCase();
  const [target, setTarget] = useState(NEW_CASE);
  const [title, setTitle] = useState(defaultTitle);
  const [doneCase, setDoneCase] = useState<number | null>(null);
  const targetId = useId();
  const titleId = useId();
  const pending = link.isPending || create.isPending;
  const error = link.error ?? create.error;

  function finish(caseId: number) {
    setDoneCase(caseId);
    onDone?.(caseId);
  }

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (alertIds.length === 0) return;
    if (target === NEW_CASE) {
      if (!title.trim()) return;
      create.mutate(
        { title: title.trim(), alert_ids: alertIds },
        {
          onSuccess: (detail) => {
            finish(detail.id);
          },
        },
      );
    } else {
      const caseId = Number(target);
      link.mutate(
        { caseId, alertIds },
        {
          onSuccess: () => {
            finish(caseId);
          },
        },
      );
    }
  }

  return (
    <form className="inline-form" onSubmit={handleSubmit} aria-label="Add to case">
      <div className="inline-field">
        <label htmlFor={targetId} className="muted small">
          Case
        </label>
        <select
          id={targetId}
          value={target}
          onChange={(event) => {
            setTarget(event.target.value);
          }}
        >
          <option value={NEW_CASE}>New case…</option>
          {cases.data?.items.map((item) => (
            <option key={item.id} value={item.id}>
              #{item.id} {item.title}
            </option>
          ))}
        </select>
      </div>
      {target === NEW_CASE ? (
        <div className="inline-field grow">
          <label htmlFor={titleId} className="muted small">
            Title
          </label>
          <input
            id={titleId}
            type="text"
            className="grow"
            maxLength={255}
            value={title}
            onChange={(event) => {
              setTitle(event.target.value);
            }}
          />
        </div>
      ) : null}
      <button
        type="submit"
        className="button button--small"
        disabled={pending || alertIds.length === 0 || (target === NEW_CASE && !title.trim())}
      >
        {target === NEW_CASE ? 'Open case' : 'Add to case'}
      </button>
      {doneCase !== null ? (
        <span className="text-ok small" role="status">
          Saved to <Link to={`/cases/${String(doneCase)}`}>case #{doneCase}</Link>.
        </span>
      ) : null}
      {error ? (
        <span className="text-error small" role="alert">
          {error.message}
        </span>
      ) : null}
    </form>
  );
}
