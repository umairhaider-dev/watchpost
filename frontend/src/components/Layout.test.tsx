import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { renderAt, stubApi } from '../test/utils';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Layout', () => {
  it('shows the API version in the sidebar', async () => {
    stubApi((path) =>
      path === '/health'
        ? { status: 200, body: { status: 'ok', version: '0.1.0', environment: 'test' } }
        : undefined,
    );

    renderAt('/');

    expect(await screen.findByText('v0.1.0 · test')).toBeInTheDocument();
  });

  it('navigates between sections and marks the active link', async () => {
    stubApi(() => undefined);
    const user = userEvent.setup();

    renderAt('/');
    await user.click(screen.getByRole('link', { name: 'Event schema' }));

    expect(await screen.findByRole('heading', { name: 'Event schema' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Event schema' })).toHaveClass('active');
    expect(screen.getByRole('link', { name: 'Overview' })).not.toHaveClass('active');
  });

  it('links to the threat intel page', async () => {
    stubApi(() => undefined);
    const user = userEvent.setup();

    renderAt('/');
    await user.click(screen.getByRole('link', { name: 'Threat intel' }));

    expect(await screen.findByRole('heading', { name: 'Threat intel' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Threat intel' })).toHaveClass('active');
  });

  it('renders a not-found page for unknown routes', async () => {
    stubApi(() => undefined);

    renderAt('/does-not-exist');

    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});
