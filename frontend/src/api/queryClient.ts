import { type DefaultOptions, MutationCache, QueryCache, QueryClient } from '@tanstack/react-query';

import { sessionKey } from './auth';
import { ApiError } from './client';

/**
 * The app's query client. A 401 from any request means the session has ended
 * (it expired, was revoked or the account was disabled), so the cached user is
 * dropped and the sign-in gate takes over.
 */
export function createQueryClient(defaultOptions: DefaultOptions = {}): QueryClient {
  const onError = (error: Error) => {
    if (error instanceof ApiError && error.status === 401 && client.getQueryData(sessionKey)) {
      client.setQueryData(sessionKey, null);
    }
  };
  const client: QueryClient = new QueryClient({
    queryCache: new QueryCache({ onError }),
    mutationCache: new MutationCache({ onError }),
    defaultOptions,
  });
  return client;
}
