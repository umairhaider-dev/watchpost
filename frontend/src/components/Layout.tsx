import { NavLink, Outlet } from 'react-router';

import { useHealth } from '../api/queries';

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

export function Layout() {
  const health = useHealth();

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <svg className="brand__mark" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M16 5 6 9v6.5c0 6 4.2 10.4 10 11.5 5.8-1.1 10-5.5 10-11.5V9L16 5z" />
            <circle cx="16" cy="15.5" r="3.2" />
          </svg>
          <span className="brand__name">Watchpost</span>
        </div>
        <nav className="nav" aria-label="Main">
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className="nav__link">
              {item.label}
            </NavLink>
          ))}
        </nav>
        <footer className="sidebar__footer">
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
        <Outlet />
      </main>
    </div>
  );
}
