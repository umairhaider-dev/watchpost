import { useQueryClient } from '@tanstack/react-query';
import { type DragEvent, type SubmitEvent, useId, useRef, useState } from 'react';

import { uploadLogFile, type UploadOptions } from '../../api/client';
import { queryKeys } from '../../api/queries';
import type { IngestInfo, IngestionJob } from '../../api/types';
import { formatBytes } from '../../lib/format';
import { Card } from '../Card';

const HOST_NAME_PATTERN = '[A-Za-z0-9][A-Za-z0-9._\\-]{0,254}';

export function UploadCard({ info }: { info: IngestInfo | undefined }) {
  const queryClient = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const parserId = useId();
  const hostId = useId();

  const [file, setFile] = useState<File | null>(null);
  const [parser, setParser] = useState('auto');
  const [hostName, setHostName] = useState('');
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [queuedJob, setQueuedJob] = useState<IngestionJob | null>(null);

  const maxBytes = info?.max_upload_bytes;
  const tooLarge = file !== null && maxBytes !== undefined && file.size > maxBytes;
  const uploading = progress !== null;
  const selectedParser = info?.parsers.find((candidate) => candidate.name === parser);

  function chooseFile(next: File | null) {
    setFile(next);
    setError(null);
    setQueuedJob(null);
  }

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragging(false);
    chooseFile(event.dataTransfer.files[0] ?? null);
  }

  async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || tooLarge) return;
    setError(null);
    setProgress(0);
    const host = hostName.trim();
    const options: UploadOptions = {
      parser,
      onProgress: setProgress,
      ...(host ? { hostName: host } : {}),
    };
    try {
      const job = await uploadLogFile(file, options);
      setQueuedJob(job);
      setFile(null);
      if (inputRef.current) inputRef.current.value = '';
      await queryClient.invalidateQueries({ queryKey: queryKeys.ingestJobs });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Upload failed');
    } finally {
      setProgress(null);
    }
  }

  return (
    <Card title="Upload a log file">
      <form
        className="form"
        onSubmit={(event) => {
          void handleSubmit(event);
        }}
      >
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
            className="visually-hidden"
            aria-label="Log file"
            onChange={(event) => {
              chooseFile(event.target.files?.[0] ?? null);
            }}
          />
          <span className="dropzone__title">
            {file ? file.name : 'Drop a log file here, or click to choose one'}
          </span>
          <span className="muted">
            {file
              ? formatBytes(file.size)
              : `Text, JSON or .gz${maxBytes ? `, up to ${formatBytes(maxBytes)}` : ''}`}
          </span>
        </label>
        {tooLarge ? (
          <p className="text-error" role="alert">
            This file is larger than the {formatBytes(maxBytes)} upload limit.
          </p>
        ) : null}

        <div className="form__row">
          <div className="field">
            <label htmlFor={parserId}>Format</label>
            <select
              id={parserId}
              value={parser}
              onChange={(event) => {
                setParser(event.target.value);
              }}
            >
              <option value="auto">Detect automatically</option>
              {info?.parsers.map((candidate) => (
                <option key={candidate.name} value={candidate.name}>
                  {candidate.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={hostId}>Host name (optional)</label>
            <input
              id={hostId}
              type="text"
              placeholder="e.g. web-01"
              pattern={HOST_NAME_PATTERN}
              maxLength={255}
              value={hostName}
              onChange={(event) => {
                setHostName(event.target.value);
              }}
            />
          </div>
        </div>
        <p className="muted small">
          {selectedParser
            ? selectedParser.description
            : 'The format is guessed from the first lines of the file.'}{' '}
          The host name is only used for events that do not record one, such as web access logs.
        </p>

        {uploading ? (
          <div
            className="progress"
            role="progressbar"
            aria-valuenow={Math.round(progress * 100)}
            aria-valuemin={0}
            aria-valuemax={100}
          >
            <div
              className="progress__bar"
              style={{ width: `${String(Math.round(progress * 100))}%` }}
            />
          </div>
        ) : null}
        {error ? (
          <p className="text-error" role="alert">
            {error}
          </p>
        ) : null}
        {queuedJob ? (
          <p className="text-ok" role="status">
            Queued {queuedJob.filename} as job #{queuedJob.id}.
          </p>
        ) : null}

        <div>
          <button type="submit" className="button" disabled={!file || tooLarge || uploading}>
            {uploading ? 'Uploading…' : 'Upload and ingest'}
          </button>
        </div>
      </form>
    </Card>
  );
}
