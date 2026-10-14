import { Link } from 'react-router';

import type { EntityKind } from '../api/types';

function entityPath(kind: EntityKind, value: string): string {
  return `/entities/${kind}?${new URLSearchParams({ value }).toString()}`;
}

/** A host, user or IP address that opens its entity page; a dash when empty. */
export function EntityLink({ kind, value }: { kind: EntityKind; value: string | null }) {
  if (!value) return <>—</>;
  return (
    <Link className="link mono" to={entityPath(kind, value)}>
      {value}
    </Link>
  );
}
