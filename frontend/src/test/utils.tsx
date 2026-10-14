import { QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { vi } from 'vitest';

import { createQueryClient } from '../api/queryClient';
import type { CurrentUser } from '../api/types';
import { routes } from '../routes';

/** Render the full app at ``path`` with a fresh query cache. */
export function renderAt(path: string) {
  const queryClient = createQueryClient({ queries: { retry: false } });
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

export interface StubRequest {
  method: string;
  body: unknown;
}

export interface StubReply {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}

type Responder = (
  path: string,
  params: URLSearchParams,
  request: StubRequest,
) => StubReply | undefined;

/** The URL a ``fetch`` call was made with. */
export function requestUrl(input: RequestInfo | URL | undefined): URL {
  const raw =
    input === undefined
      ? ''
      : typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
  return new URL(raw, 'http://localhost');
}

/** Who ``stubApi`` reports as signed in by default. */
export const signedInAdmin: CurrentUser = {
  id: 1,
  username: 'test.admin',
  full_name: 'Test Admin',
  email: null,
  role: 'admin',
};

export interface StubOptions {
  /** The user ``/auth/me`` returns; ``null`` answers 401 (signed out). */
  user?: CurrentUser | null;
}

/** Replace ``fetch`` with a stub that answers API paths via ``respond``. */
export function stubApi(respond: Responder, { user = signedInAdmin }: StubOptions = {}) {
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = requestUrl(input);
    const path = url.pathname.replace(/^\/api/, '');
    const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
    const reply: StubReply =
      path === '/auth/me'
        ? user
          ? { status: 200, body: user }
          : { status: 401, body: { detail: 'not signed in' } }
        : (respond(path, url.searchParams, { method: init?.method ?? 'GET', body }) ?? {
            status: 404,
            body: { detail: 'Not Found' },
          });
    const payload = reply.status === 204 ? null : JSON.stringify(reply.body ?? null);
    return Promise.resolve(
      new Response(payload, {
        status: reply.status,
        headers: { 'Content-Type': 'application/json', ...reply.headers },
      }),
    );
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}
