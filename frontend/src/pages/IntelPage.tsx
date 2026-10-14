import { AddIocCard } from '../components/intel/AddIocCard';
import { FeedImportCard } from '../components/intel/FeedImportCard';
import { IntelStatsCard } from '../components/intel/IntelStatsCard';
import { IocTable } from '../components/intel/IocTable';
import { LookupCard } from '../components/intel/LookupCard';
import { ProvidersCard } from '../components/intel/ProvidersCard';
import { PageHeader } from '../components/PageHeader';

export function IntelPage() {
  return (
    <>
      <PageHeader
        title="Threat intel"
        description="Known-bad IP addresses, domains and file hashes. New events are checked against them as they arrive, and stored events are checked again whenever indicators are added."
      />
      <div className="grid grid--wide">
        <div className="stack stack--flush">
          <IntelStatsCard />
          <IocTable />
        </div>
        <div className="stack stack--flush">
          <LookupCard />
          <FeedImportCard />
          <AddIocCard />
          <ProvidersCard />
        </div>
      </div>
    </>
  );
}
