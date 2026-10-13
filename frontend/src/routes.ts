import type { RouteObject } from 'react-router';

import { Layout } from './components/Layout';
import { EventsPage } from './pages/EventsPage';
import { IngestPage } from './pages/IngestPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OverviewPage } from './pages/OverviewPage';
import { SchemaPage } from './pages/SchemaPage';

export const routes: RouteObject[] = [
  {
    path: '/',
    Component: Layout,
    children: [
      { index: true, Component: OverviewPage },
      { path: 'ingest', Component: IngestPage },
      { path: 'events', Component: EventsPage },
      { path: 'schema', Component: SchemaPage },
      { path: '*', Component: NotFoundPage },
    ],
  },
];
