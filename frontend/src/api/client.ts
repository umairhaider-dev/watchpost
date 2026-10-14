import type { IngestionJob } from './types';

const API_PREFIX = '/api';

/** The readable cookie holding this session's CSRF secret, set by the API at sign-in. */
export const CSRF_COOKIE = 'watchpost_csrf';
/** Requests that change data must echo that secret in this header. */
export const CSRF_HEADER = 'X-CSRF-Token';

export class ApiError extends Error {
  readonly status: number;
  /** Seconds to wait before retrying, from a Retry-After header (e.g. on 429). */
  readonly retryAfterSeconds: number | null;

  constructor(status: number, message: string, retryAfterSeconds: number | null = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** This session's CSRF secret, or null when signed out. */
export function csrfToken(): string | null {
  for (const part of document.cookie.split(';')) {
    const [name = '', ...value] = part.trim().split('=');
    if (name === CSRF_COOKIE) return decodeURIComponent(value.join('='));
  }
  return null;
}

/** Headers for a request that changes data: JSON answers and the CSRF secret. */
function writeHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = { Accept: 'application/json', ...extra };
  const token = csrfToken();
  if (token) headers[CSRF_HEADER] = token;
  return headers;
}

/** Pull a readable message out of a FastAPI error body ({"detail": ...}). */
export function errorDetail(body: unknown): string | null {
  if (typeof body !== 'object' || body === null || !('detail' in body)) return null;
  const { detail } = body;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item: unknown) =>
        typeof item === 'object' && item !== null && 'msg' in item ? String(item.msg) : null,
      )
      .filter((message): message is string => message !== null);
    return messages.length > 0 ? messages.join('; ') : null;
  }
  return null;
}

export interface RequestOptions {
  signal?: AbortSignal;
  /** Non-2xx statuses whose JSON body should still be returned (e.g. 503 from readiness). */
  acceptStatuses?: readonly number[];
  params?: Record<string, string | number | undefined>;
}

async function failure(response: Response, fallback: string): Promise<ApiError> {
  const body: unknown = await response.json().catch(() => null);
  const retryAfter = Number(response.headers.get('Retry-After'));
  return new ApiError(
    response.status,
    errorDetail(body) ?? fallback,
    Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null,
  );
}

function buildUrl(path: string, params: RequestOptions['params']): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined && value !== '') query.set(key, String(value));
  }
  const suffix = query.toString();
  return `${API_PREFIX}${path}${suffix ? `?${suffix}` : ''}`;
}

export async function apiGet<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await fetch(buildUrl(path, options.params), {
    headers: { Accept: 'application/json' },
    signal: options.signal ?? null,
  });
  const accepted = response.ok || (options.acceptStatuses ?? []).includes(response.status);
  if (!accepted) {
    throw await failure(response, `GET ${path} failed with HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

export type WriteMethod = 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** Send a JSON request; returns the parsed response (undefined for 204). */
export async function apiSend<T>(method: WriteMethod, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, headers: writeHeaders() };
  if (body !== undefined) {
    init.headers = writeHeaders({ 'Content-Type': 'application/json' });
    init.body = JSON.stringify(body);
  }
  const response = await fetch(`${API_PREFIX}${path}`, init);
  if (!response.ok) {
    throw await failure(response, `${method} ${path} failed with HTTP ${response.status}`);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** POST a multipart form (small files such as indicator feeds). */
export async function apiPostForm<T>(path: string, form: FormData): Promise<T> {
  const response = await fetch(`${API_PREFIX}${path}`, {
    method: 'POST',
    headers: writeHeaders(),
    body: form,
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(
      response.status,
      errorDetail(body) ?? `POST ${path} failed with HTTP ${response.status}`,
    );
  }
  return body as T;
}

export interface UploadOptions {
  parser: string;
  hostName?: string;
  /** Called with the fraction (0..1) of the file sent so far. */
  onProgress?: (fraction: number) => void;
}

/**
 * Upload a log file for ingestion. Uses XMLHttpRequest because fetch cannot
 * report upload progress, which matters for large log files.
 */
export function uploadLogFile(file: File, options: UploadOptions): Promise<IngestionJob> {
  return new Promise((resolve, reject) => {
    const form = new FormData();
    form.append('file', file);
    form.append('parser', options.parser);
    if (options.hostName) form.append('host_name', options.hostName);

    const request = new XMLHttpRequest();
    request.open('POST', `${API_PREFIX}/ingest/uploads`);
    for (const [name, value] of Object.entries(writeHeaders())) {
      request.setRequestHeader(name, value);
    }
    request.responseType = 'json';
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) options.onProgress?.(event.loaded / event.total);
    };
    request.onload = () => {
      const body: unknown = request.response;
      if (request.status === 202) {
        resolve(body as IngestionJob);
      } else {
        reject(
          new ApiError(
            request.status,
            errorDetail(body) ?? `Upload failed with HTTP ${request.status}`,
          ),
        );
      }
    };
    request.onerror = () => {
      reject(new ApiError(0, 'Network error while uploading the file'));
    };
    request.send(form);
  });
}
