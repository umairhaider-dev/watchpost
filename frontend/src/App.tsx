import { QueryClientProvider } from '@tanstack/react-query';
import { createBrowserRouter, RouterProvider } from 'react-router';

import { createQueryClient } from './api/queryClient';
import { routes } from './routes';

const queryClient = createQueryClient({
  queries: { retry: 1, refetchOnWindowFocus: false },
});

const router = createBrowserRouter(routes);

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}
