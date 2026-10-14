import { Link, NavLink, Outlet } from 'react-router';

import { useCurrentUser, usePermissions, useSignOut } from '../api/auth';
import { useHealth } from '../api/queries';
import { roleLabel } from '../lib/labels';
import { Brand } from './Brand';

const NAV_ITEMS = [
  { to: '/', label: 'Overview', end: true },
  { to: '/alerts', label: 'Alerts', end: false },
  { to: '/cases', label: 'Cases', end: false },
  { to: '/events', label: 'Event search', end: false },
  { to: '/mitre', label: 'ATT&CK matrix', end: false },
  { to: '/rules', label: 'Rules', end: false },
  { to: '/intel', label: 'Threat intel', end: false },
  { to: '/ingest', label: 'Ingest', end: false },
  { to: '/schema', label: 'Event schema', end: false },
] as const;

const ADMIN_ITEMS = [
  { to: '/users', label: 'Users' },
  { to: '/audit', label: 'Audit log' },
] as const;

function SessionPanel() {
  const user = useCurrentUser().data;
  const signOut = useSignOut();

  if (!user) return null;
  return (
    <div className="session">
      <Link className="session__user" to="/account" title="Your account">
        <span className="session__name">{user.full_name ?? user.username}</span>
        <span className="muted small">
          {user.username} · {roleLabel(user.role)}
        </span>
      </Link>
      <button
        type="button"
        className="link small"
        disabled={signOut.isPending}
        onClick={() => {
          signOut.mutate(false);
        }}
      >
        Sign out
      </button>
    </div>
  );
}

export function Layout() {
  const health = useHealth();
  const { canEdit, isAdmin } = usePermissions();

  return (
    <div className="shell">
      <aside className="sidebar">
        <Brand />
        <nav className="nav" aria-label="Main">
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className="nav__link">
              {item.label}
            </NavLink>
          ))}
          {isAdmin ? (
            <>
              <span className="nav__section">Administration</span>
              {ADMIN_ITEMS.map((item) => (
                <NavLink key={item.to} to={item.to} className="nav__link">
                  {item.label}
                </NavLink>
              ))}
            </>
          ) : null}
        </nav>
        <footer className="sidebar__footer">
          <SessionPanel />
          {health.data ? (
            <span>
              v{health.data.version} · {health.data.environment}
            </span>
          ) : (
            <span>API unreachable</span>
          )}
        </footer>
      </aside>
      <main className="content">
        {canEdit ? null : (
          <p className="notice" role="note">
            You have read-only access. Ask an administrator if you need to triage alerts or work on
            cases.
          </p>
        )}
        <Outlet />
      </main>
    </div>
  );
}
