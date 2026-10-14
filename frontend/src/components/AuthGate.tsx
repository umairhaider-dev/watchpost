import { Navigate, Outlet, useLocation } from 'react-router';

import { useCurrentUser, usePermissions } from '../api/auth';
import { PageHeader } from './PageHeader';

/** Where the sign-in page should return to, carried in the router state. */
export interface ReturnState {
  from: string;
}

/**
 * Shows the app to signed-in users and sends everyone else to the sign-in page,
 * remembering where they were going. The API enforces the same rule.
 */
export function AuthGate() {
  const session = useCurrentUser();
  const location = useLocation();

  if (session.isPending) {
    return (
      <p className="splash muted" role="status">
        Loading…
      </p>
    );
  }
  if (session.isError) {
    return (
      <div className="splash" role="alert">
        <p className="text-error">Could not reach the Watchpost API.</p>
        <button
          type="button"
          className="button button--secondary"
          onClick={() => {
            void session.refetch();
          }}
        >
          Try again
        </button>
      </div>
    );
  }
  if (!session.data) {
    const state: ReturnState = { from: `${location.pathname}${location.search}` };
    return <Navigate to="/login" replace state={state} />;
  }
  return <Outlet />;
}

/** Wraps pages only admins may open. The API refuses everyone else as well. */
export function AdminOnly() {
  const { isAdmin } = usePermissions();

  if (!isAdmin) {
    return (
      <PageHeader
        title="Admins only"
        description="This page is only available to administrators. Ask one if you need access."
      />
    );
  }
  return <Outlet />;
}
