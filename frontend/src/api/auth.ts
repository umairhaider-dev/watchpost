import { type QueryClient, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ApiError, apiGet, apiSend } from './client';
import type { CurrentUser, SignedIn, UserRole } from './types';

/** Cache key of the signed-in user; ``null`` data means signed out. */
export const sessionKey = ['auth', 'me'] as const;

const ROLE_RANK: Record<UserRole, number> = { viewer: 0, analyst: 1, admin: 2 };

/** Whether ``role`` may do everything ``required`` may (admin > analyst > viewer). */
export function roleAllows(role: UserRole, required: UserRole): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[required];
}

async function fetchCurrentUser(signal: AbortSignal): Promise<CurrentUser | null> {
  try {
    return await apiGet<CurrentUser>('/auth/me', { signal });
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null;
    throw error;
  }
}

/** The signed-in user, or ``null`` when there is no valid session. */
export function useCurrentUser() {
  return useQuery({
    queryKey: sessionKey,
    queryFn: ({ signal }) => fetchCurrentUser(signal),
    staleTime: Infinity,
    retry: false,
  });
}

export interface Permissions {
  /** Analysts and admins: triage, cases, uploads, intel and detection runs. */
  canEdit: boolean;
  /** Admins: rule changes, user management and the audit log. */
  isAdmin: boolean;
}

/** What the signed-in user may change. Every role may read everything else. */
export function usePermissions(): Permissions {
  const role = useCurrentUser().data?.role;
  return {
    canEdit: role !== undefined && roleAllows(role, 'analyst'),
    isAdmin: role === 'admin',
  };
}

/** Drop everything cached except the session itself, so no data outlives a user. */
function forgetCachedData(queryClient: QueryClient) {
  queryClient.removeQueries({ predicate: (query) => query.queryKey[0] !== sessionKey[0] });
}

export interface Credentials {
  username: string;
  password: string;
}

export function useSignIn() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (credentials: Credentials) => apiSend<SignedIn>('POST', '/auth/login', credentials),
    onSuccess: (signedIn) => {
      forgetCachedData(queryClient);
      queryClient.setQueryData(sessionKey, signedIn.user);
    },
  });
}

/** Sign out; with ``everywhere`` every other session of the account ends too. */
export function useSignOut() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (everywhere: boolean) =>
      apiSend<undefined>('POST', everywhere ? '/auth/logout?everywhere=true' : '/auth/logout'),
    onSuccess: () => {
      queryClient.setQueryData(sessionKey, null);
      forgetCachedData(queryClient);
    },
  });
}

export interface PasswordChange {
  current_password: string;
  new_password: string;
}

/** Change one's own password; other sessions end, this one carries on. */
export function useChangePassword() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (change: PasswordChange) => apiSend<SignedIn>('POST', '/auth/password', change),
    onSuccess: (signedIn) => {
      queryClient.setQueryData(sessionKey, signedIn.user);
    },
  });
}
