import { usePermissions } from '../api/auth';
import { useIngestInfo } from '../api/queries';
import { JobsTable } from '../components/ingest/JobsTable';
import { UploadCard } from '../components/ingest/UploadCard';
import { WatchFolderCard } from '../components/ingest/WatchFolderCard';
import { PageHeader } from '../components/PageHeader';

export function IngestPage() {
  const info = useIngestInfo();
  const { canEdit } = usePermissions();

  return (
    <>
      <PageHeader
        title="Ingest"
        description="Upload log files or drop them in the watched folder. Every event is deduplicated, so the same file can safely be ingested twice."
      />
      <div className="grid grid--wide">
        {canEdit ? <UploadCard info={info.data} /> : null}
        <WatchFolderCard info={info.data} />
      </div>
      <div className="stack">
        <JobsTable />
      </div>
    </>
  );
}
