import { type SubmitEvent, useId, useState } from 'react';

import { useLookup } from '../../api/queries';
import { IOC_TYPE_LABELS } from '../../lib/intel';
import { Card } from '../Card';
import { LocalIntel, ProviderResults } from './IndicatorContext';
import { VerdictBadge } from './VerdictBadge';

export function LookupCard() {
  const lookup = useLookup();
  const [value, setValue] = useState('');
  const inputId = useId();
  const result = lookup.data;

  function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (value.trim()) lookup.mutate({ value: value.trim(), refresh: false });
  }

  return (
    <Card title="Look up an indicator">
      <form className="form" onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor={inputId}>IP address, domain or file hash</label>
          <div className="inline-field">
            <input
              id={inputId}
              type="text"
              className="grow"
              placeholder="e.g. 203.0.113.45 or evil[.]example"
              maxLength={2048}
              value={value}
              onChange={(event) => {
                setValue(event.target.value);
              }}
            />
            <button type="submit" className="button" disabled={lookup.isPending || !value.trim()}>
              {lookup.isPending ? 'Looking up…' : 'Look up'}
            </button>
          </div>
        </div>
      </form>
      {lookup.isError ? (
        <p className="text-error small" role="alert">
          {lookup.error.message}
        </p>
      ) : null}
      {result ? (
        <div className="indicator" aria-label="Lookup result">
          <div className="indicator__head">
            <span className="mono indicator__value">{result.value}</span>
            <span className="badge">{IOC_TYPE_LABELS[result.ioc_type]}</span>
            <VerdictBadge verdict={result.verdict} />
          </div>
          <LocalIntel hits={result.intel} />
          {result.providers.length > 0 ? <ProviderResults results={result.providers} /> : null}
          {!result.shared ? (
            <p className="muted small">Internal or reserved, so never sent to online providers.</p>
          ) : null}
          {result.shared && !result.online ? (
            <p className="muted small">No online providers are configured.</p>
          ) : null}
          {result.providers.length > 0 ? (
            <button
              type="button"
              className="link small"
              disabled={lookup.isPending}
              onClick={() => {
                lookup.mutate({ value: result.value, refresh: true });
              }}
            >
              Ask the providers again
            </button>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
