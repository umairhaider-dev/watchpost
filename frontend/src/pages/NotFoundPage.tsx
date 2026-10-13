import { Link } from 'react-router';

import { PageHeader } from '../components/PageHeader';

export function NotFoundPage() {
  return (
    <>
      <PageHeader title="Page not found" description="There is nothing at this address." />
      <Link className="link" to="/">
        Back to overview
      </Link>
    </>
  );
}
