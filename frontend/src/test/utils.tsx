import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { vi } from 'vitest';

import { routes } from '../routes';

/** Render the full app at ``path`` with a fresh query cache. */
export function renderAt(path: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

type Responder = (
  path: string,
  params: URLSearchParams,
) => { status: number; body: unknown } | undefined;

/** Replace ``fetch`` with a stub that answers API paths via ``respond``. */
export function stubApi(respond: Responder) {
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const url = new URL(raw, 'http://localhost');
    const path = url.pathname.replace(/^\/api/, '');
    const reply = respond(path, url.searchParams) ?? {
      status: 404,
      body: { detail: 'Not Found' },
    };
    return Promise.resolve(
      new Response(JSON.stringify(reply.body), {
        status: reply.status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}
