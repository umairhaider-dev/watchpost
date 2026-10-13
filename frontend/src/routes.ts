import type { RouteObject } from 'react-router';

import { Layout } from './components/Layout';
import { AlertsPage } from './pages/AlertsPage';
import { EventsPage } from './pages/EventsPage';
import { IngestPage } from './pages/IngestPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OverviewPage } from './pages/OverviewPage';
import { RuleDetailPage } from './pages/RuleDetailPage';
import { RulesPage } from './pages/RulesPage';
import { SchemaPage } from './pages/SchemaPage';

export const routes: RouteObject[] = [
  {
    path: '/',
    Component: Layout,
    children: [
      { index: true, Component: OverviewPage },
      { path: 'alerts', Component: AlertsPage },
      { path: 'rules', Component: RulesPage },
      { path: 'rules/:ruleId', Component: RuleDetailPage },
      { path: 'ingest', Component: IngestPage },
      { path: 'events', Component: EventsPage },
      { path: 'schema', Component: SchemaPage },
      { path: '*', Component: NotFoundPage },
    ],
  },
];
