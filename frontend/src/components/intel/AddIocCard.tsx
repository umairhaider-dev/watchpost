import { type SubmitEvent, useId, useState } from 'react';

import { type NewIoc, useAddIoc } from '../../api/queries';
import type { IocType } from '../../api/types';
import { IOC_TYPE_LABELS } from '../../lib/intel';
import { Card } from '../Card';

const TYPES = Object.entries(IOC_TYPE_LABELS) as [IocType, string][];

export function AddIocCard() {
  const add = useAddIoc();
  const valueId = useId();
  const typeId = useId();
  const confidenceId = useId();
  const tagsId = useId();
  const descriptionId = useId();

  const [value, setValue] = useState('');
  const [iocType, setIocType] = useState<IocType | ''>('');
  const [confidence, setConfidence] = useState('');
  const [tags, setTags] = useState('');
  const [description, setDescription] = useState('');

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!value.trim()) return;
    const payload: NewIoc = {
      value: value.trim(),
      tags: tags
        .split(',')
        .map((tag) => tag.trim())
        .filter(Boolean),
      ...(iocType ? { ioc_type: iocType } : {}),
      ...(confidence.trim() ? { confidence: Number(confidence) } : {}),
      ...(description.trim() ? { description: description.trim() } : {}),
    };
    add.mutate(payload, {
      onSuccess: () => {
        setValue('');
        setDescription('');
      },
    });
  }

  return (
    <Card title="Add an indicator">
      <form className="form" onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor={valueId}>Value</label>
          <input
            id={valueId}
            type="text"
            placeholder="IP address, domain, URL or file hash (defanged is fine)"
            maxLength={2048}
            value={value}
            onChange={(event) => {
              setValue(event.target.value);
            }}
          />
        </div>
        <div className="form__row">
          <div className="field">
            <label htmlFor={typeId}>Type</label>
            <select
              id={typeId}
              value={iocType}
              onChange={(event) => {
                setIocType(event.target.value as IocType | '');
              }}
            >
              <option value="">Detect automatically</option>
              {TYPES.map(([type, label]) => (
                <option key={type} value={type}>
                  {label}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={confidenceId}>Confidence</label>
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
        <div className="field">
          <label htmlFor={tagsId}>Tags</label>
          <input
            id={tagsId}
            type="text"
            placeholder="Comma-separated, e.g. c2, phishing"
            value={tags}
            onChange={(event) => {
              setTags(event.target.value);
            }}
          />
        </div>
        <div className="field">
          <label htmlFor={descriptionId}>Description</label>
          <input
            id={descriptionId}
            type="text"
            maxLength={2000}
            placeholder="Why it is bad, where it came from"
            value={description}
            onChange={(event) => {
              setDescription(event.target.value);
            }}
          />
        </div>
        <div className="inline-field">
          <button type="submit" className="button" disabled={add.isPending || !value.trim()}>
            {add.isPending ? 'Adding…' : 'Add indicator'}
          </button>
          {add.isSuccess ? (
            <span className="text-ok small" role="status">
              Saved {add.data.value}; stored events are being checked for it.
            </span>
          ) : null}
        </div>
        {add.isError ? (
          <p className="text-error small" role="alert">
            {add.error.message}
          </p>
        ) : null}
      </form>
    </Card>
  );
}
