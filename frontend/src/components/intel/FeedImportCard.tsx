import { type DragEvent, type SubmitEvent, useId, useRef, useState } from 'react';

import { useImportFeed } from '../../api/queries';
import { formatBytes, formatNumber } from '../../lib/format';
import { Card } from '../Card';

const MAX_FEED_BYTES = 20 * 1024 * 1024;
const PROBLEMS_SHOWN = 5;

export function FeedImportCard() {
  const importFeed = useImportFeed();
  const inputRef = useRef<HTMLInputElement>(null);
  const sourceId = useId();
  const confidenceId = useId();
  const tagsId = useId();
  const expiresId = useId();

  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [source, setSource] = useState('');
  const [confidence, setConfidence] = useState('');
  const [tags, setTags] = useState('');
  const [expiresInDays, setExpiresInDays] = useState('');
  const tooLarge = file !== null && file.size > MAX_FEED_BYTES;
  const result = importFeed.data;

  function chooseFile(next: File | null) {
    setFile(next);
    importFeed.reset();
  }

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragging(false);
    chooseFile(event.dataTransfer.files[0] ?? null);
  }

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || tooLarge) return;
    importFeed.mutate(
      { file, source, confidence, tags, expiresInDays },
      {
        onSuccess: () => {
          setFile(null);
          if (inputRef.current) inputRef.current.value = '';
        },
      },
    );
  }

  return (
    <Card title="Import a feed">
      <form className="form" onSubmit={handleSubmit}>
        <label
          className="dropzone"
          data-dragging={dragging}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => {
            setDragging(false);
          }}
          onDrop={handleDrop}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".txt,.csv,text/plain,text/csv"
            className="visually-hidden"
            aria-label="Feed file"
            onChange={(event) => {
              chooseFile(event.target.files?.[0] ?? null);
            }}
          />
          <span className="dropzone__title">
            {file ? file.name : 'Drop a TXT or CSV feed here, or click to choose one'}
          </span>
          <span className="muted">
            {file
              ? formatBytes(file.size)
              : `One indicator per line, or CSV with a value column; up to ${formatBytes(MAX_FEED_BYTES)}`}
          </span>
        </label>
        {tooLarge ? (
          <p className="text-error" role="alert">
            Feed files are limited to {formatBytes(MAX_FEED_BYTES)}.
          </p>
        ) : null}
        <div className="form__row">
          <div className="field">
            <label htmlFor={sourceId}>Source name</label>
            <input
              id={sourceId}
              type="text"
              placeholder="Defaults to the file name"
              maxLength={128}
              value={source}
              onChange={(event) => {
                setSource(event.target.value);
              }}
            />
          </div>
          <div className="field">
            <label htmlFor={confidenceId}>Default confidence</label>
            <input
              id={confidenceId}
              type="number"
              min={0}
              max={100}
              placeholder="0-100"
              value={confidence}
              onChange={(event) => {
                setConfidence(event.target.value);
              }}
            />
          </div>
        </div>
        <div className="form__row">
          <div className="field">
            <label htmlFor={tagsId}>Extra tags</label>
            <input
              id={tagsId}
              type="text"
              placeholder="Comma-separated"
              maxLength={512}
              value={tags}
              onChange={(event) => {
                setTags(event.target.value);
              }}
            />
          </div>
          <div className="field">
            <label htmlFor={expiresId}>Expires after (days)</label>
            <input
              id={expiresId}
              type="number"
              min={1}
              max={3650}
              placeholder="Never"
              value={expiresInDays}
              onChange={(event) => {
                setExpiresInDays(event.target.value);
              }}
            />
          </div>
        </div>
        <div>
          <button
            type="submit"
            className="button"
            disabled={!file || tooLarge || importFeed.isPending}
          >
            {importFeed.isPending ? 'Importing…' : 'Import feed'}
          </button>
        </div>
      </form>
      {importFeed.isError ? (
        <p className="text-error" role="alert">
          {importFeed.error.message}
        </p>
      ) : null}
      {result ? (
        <div role="status" className="import-result">
          <p className="text-ok">
            Imported {formatNumber(result.indicators)} indicators from {result.filename}:{' '}
            {formatNumber(result.created)} new, {formatNumber(result.updated)} updated
            {result.duplicates ? `, ${formatNumber(result.duplicates)} duplicate lines` : ''}.
          </p>
          <p className="muted small">
            {result.sweep_queued
              ? 'Stored events are being checked against them in the background.'
              : 'The job queue is unavailable, so stored events were not re-checked yet. Use "Re-check stored events" later.'}
          </p>
          {result.problem_count > 0 ? (
            <>
              <p className="text-warn small">
                {formatNumber(result.problem_count)} line{result.problem_count === 1 ? '' : 's'}{' '}
                skipped
                {result.truncated ? '; the feed was cut off at the size limit' : ''}:
              </p>
              <ul className="plain-list small">
                {result.problems.slice(0, PROBLEMS_SHOWN).map((problem) => (
                  <li key={problem.line}>
                    <span className="mono">line {problem.line}</span>: {problem.reason}
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
