import { useQuery } from '@tanstack/react-query';

import { apiGet } from './client';
import type { Dashboard, DashboardRange } from './types';

export const DASHBOARD_RANGES: { value: DashboardRange; label: string }[] = [
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: 'all', label: 'All time' },
];

export function useDashboard(range: DashboardRange) {
  return useQuery({
    queryKey: ['dashboard', range],
    queryFn: ({ signal }) => apiGet<Dashboard>('/dashboard', { signal, params: { range } }),
    refetchInterval: 30_000,
  });
}
