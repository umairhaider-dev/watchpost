import type { RouteObject } from 'react-router';

import { AdminOnly, AuthGate } from './components/AuthGate';
import { Layout } from './components/Layout';
import { AccountPage } from './pages/AccountPage';
import { AlertPage } from './pages/AlertPage';
import { AlertsPage } from './pages/AlertsPage';
import { AuditPage } from './pages/AuditPage';
import { CasePage } from './pages/CasePage';
import { CasesPage } from './pages/CasesPage';
import { EntityPage } from './pages/EntityPage';
import { EventsPage } from './pages/EventsPage';
import { IngestPage } from './pages/IngestPage';
import { IntelPage } from './pages/IntelPage';
import { LoginPage } from './pages/LoginPage';
import { MitrePage } from './pages/MitrePage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OverviewPage } from './pages/OverviewPage';
import { RuleDetailPage } from './pages/RuleDetailPage';
import { RulesPage } from './pages/RulesPage';
import { SchemaPage } from './pages/SchemaPage';
import { UsersPage } from './pages/UsersPage';

export const routes: RouteObject[] = [
  { path: '/login', Component: LoginPage },
  {
    Component: AuthGate,
    children: [
      {
        path: '/',
        Component: Layout,
        children: [
          { index: true, Component: OverviewPage },
          { path: 'alerts', Component: AlertsPage },
          { path: 'alerts/:alertId', Component: AlertPage },
          { path: 'cases', Component: CasesPage },
          { path: 'cases/:caseId', Component: CasePage },
          { path: 'entities/:kind', Component: EntityPage },
          { path: 'mitre', Component: MitrePage },
          { path: 'rules', Component: RulesPage },
          { path: 'rules/:ruleId', Component: RuleDetailPage },
          { path: 'intel', Component: IntelPage },
          { path: 'ingest', Component: IngestPage },
          { path: 'events', Component: EventsPage },
          { path: 'schema', Component: SchemaPage },
          { path: 'account', Component: AccountPage },
          {
            Component: AdminOnly,
            children: [
              { path: 'users', Component: UsersPage },
              { path: 'audit', Component: AuditPage },
            ],
          },
          { path: '*', Component: NotFoundPage },
        ],
      },
    ],
  },
];
