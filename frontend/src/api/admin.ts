import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { apiGet, apiSend } from './client';
import type { AuditEntryPage, UserAccount, UserRole } from './types';

export const AUDIT_PAGE_SIZE = 50;

const adminKeys = {
  users: ['users'] as const,
  accounts: ['users', 'accounts'] as const,
  audit: (filters: AuditFilters) => ['audit', filters] as const,
};

// ---------------------------------------------------------------- accounts

export function useUserAccounts() {
  return useQuery({
    queryKey: adminKeys.accounts,
    queryFn: ({ signal }) => apiGet<UserAccount[]>('/users', { signal }),
  });
}

export interface NewUser {
  username: string;
  password: string;
  role: UserRole;
  full_name: string | null;
  email: string | null;
}

export function useCreateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (user: NewUser) => apiSend<UserAccount>('POST', '/users', user),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: adminKeys.users }),
  });
}

export interface UserChanges {
  role?: UserRole;
  is_active?: boolean;
  full_name?: string | null;
}

export function useUpdateUser(id: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (changes: UserChanges) =>
      apiSend<UserAccount>('PATCH', `/users/${String(id)}`, changes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: adminKeys.users }),
  });
}

/** Set a new password for someone else; all of their sessions end. */
export function useResetPassword(id: number) {
  return useMutation({
    mutationFn: (password: string) =>
      apiSend<undefined>('POST', `/users/${String(id)}/password`, { password }),
  });
}

// ---------------------------------------------------------------- audit log

export interface AuditFilters {
  /** An exact action, or a prefix ending in "." such as "rule.". */
  action: string;
  username: string;
  offset: number;
}

export function useAuditLog(filters: AuditFilters) {
  return useQuery({
    queryKey: adminKeys.audit(filters),
    queryFn: ({ signal }) =>
      apiGet<AuditEntryPage>('/audit', {
        signal,
        params: {
          action: filters.action,
          username: filters.username,
          limit: AUDIT_PAGE_SIZE,
          offset: filters.offset,
        },
      }),
    placeholderData: keepPreviousData,
  });
}
