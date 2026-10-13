import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { FieldInfo } from '../api/types';
import { renderAt, stubApi } from '../test/utils';

const FIELDS: FieldInfo[] = [
  { name: '@timestamp', kind: 'datetime', description: 'When the event happened (UTC).' },
  { name: 'source.ip', kind: 'ip', description: 'Address the activity came from.' },
];

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('SchemaPage', () => {
  it('lists every normalised field with its type', async () => {
    stubApi((path) => (path === '/meta/fields' ? { status: 200, body: FIELDS } : undefined));

    renderAt('/schema');

    expect(await screen.findByText('source.ip')).toBeInTheDocument();
    expect(screen.getByText('@timestamp')).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(FIELDS.length + 1);
  });

  it('shows an error when the field list fails to load', async () => {
    stubApi(() => ({ status: 500, body: {} }));

    renderAt('/schema');

    expect(await screen.findByText('Could not load the field list.')).toBeInTheDocument();
  });
});
