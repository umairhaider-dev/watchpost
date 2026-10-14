import { afterEach, describe, expect, it, vi } from 'vitest';

import { stubApi } from '../test/utils';
import {
  ApiError,
  apiGet,
  apiPostForm,
  apiSend,
  CSRF_COOKIE,
  CSRF_HEADER,
  csrfToken,
  uploadLogFile,
} from './client';

function setCsrfCookie(value: string) {
  document.cookie = `${CSRF_COOKIE}=${value}; path=/`;
}

afterEach(() => {
  document.cookie = `${CSRF_COOKIE}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  vi.unstubAllGlobals();
});

function sentHeaders(fetchMock: ReturnType<typeof stubApi>): Headers[] {
  return fetchMock.mock.calls.map(([, init]) => new Headers(init?.headers));
}

describe('CSRF protection', () => {
  it('reads the secret from its cookie', () => {
    expect(csrfToken()).toBeNull();
    document.cookie = 'theme=dark; path=/';
    setCsrfCookie('s3cr3t-value');

    expect(csrfToken()).toBe('s3cr3t-value');
  });

  it('echoes the secret on changes but not on reads', async () => {
    setCsrfCookie('s3cr3t-value');
    const fetchMock = stubApi(() => ({ status: 200, body: {} }));

    await apiGet('/alerts');
    await apiSend('PATCH', '/alerts/1', { status: 'closed' });
    await apiSend('DELETE', '/intel/iocs/1');
    await apiPostForm('/intel/feeds', new FormData());

    const headers = sentHeaders(fetchMock);
    expect(headers.map((sent) => sent.get(CSRF_HEADER))).toEqual([
      null,
      's3cr3t-value',
      's3cr3t-value',
      's3cr3t-value',
    ]);
    expect(headers[1]?.get('Content-Type')).toBe('application/json');
  });

  it('sends no header when there is no session', async () => {
    const fetchMock = stubApi(() => ({ status: 200, body: {} }));

    await apiSend('POST', '/auth/login', { username: 'analyst.one', password: 'x' });

    expect(sentHeaders(fetchMock)[0]?.has(CSRF_HEADER)).toBe(false);
  });

  it('adds the secret to log uploads', async () => {
    setCsrfCookie('s3cr3t-value');
    const sent: Record<string, string> = {};
    class FakeRequest {
      upload = { onprogress: null };
      responseType = '';
      status = 202;
      response: unknown = { id: 5 };
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      open() {
        // Nothing to connect to.
      }
      setRequestHeader(name: string, value: string) {
        sent[name] = value;
      }
      send() {
        this.onload?.();
      }
    }
    vi.stubGlobal('XMLHttpRequest', FakeRequest);

    await expect(
      uploadLogFile(new File(['line\n'], 'auth.log'), { parser: 'linux_auth' }),
    ).resolves.toEqual({ id: 5 });
    expect(sent[CSRF_HEADER]).toBe('s3cr3t-value');
  });
});

describe('errors', () => {
  it('carry the status, the API message and any Retry-After', async () => {
    stubApi(() => ({
      status: 429,
      body: { detail: 'too many failed sign-ins; try again later' },
      headers: { 'Retry-After': '120' },
    }));

    const error: unknown = await apiSend('POST', '/auth/login', {}).catch((caught: unknown) => {
      return caught;
    });

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 429,
      message: 'too many failed sign-ins; try again later',
      retryAfterSeconds: 120,
    });
  });

  it('leave Retry-After empty when the API sends none', async () => {
    stubApi(() => ({ status: 500, body: null }));

    await expect(apiGet('/alerts')).rejects.toMatchObject({
      status: 500,
      message: 'GET /alerts failed with HTTP 500',
      retryAfterSeconds: null,
    });
  });
});
