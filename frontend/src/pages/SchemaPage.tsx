import { useEventFields } from '../api/queries';
import { Card } from '../components/Card';
import { PageHeader } from '../components/PageHeader';

export function SchemaPage() {
  const fields = useEventFields();

  return (
    <>
      <PageHeader
        title="Event schema"
        description="Normalised fields every parser maps logs onto. Detection rules and searches use these names."
      />
      <Card
        title="Fields"
        aside={fields.data ? <span className="muted">{fields.data.length}</span> : null}
      >
        {fields.isPending ? <p className="muted">Loading fields…</p> : null}
        {fields.isError ? <p className="text-error">Could not load the field list.</p> : null}
        {fields.data ? (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Field</th>
                  <th scope="col">Type</th>
                  <th scope="col">Description</th>
                </tr>
              </thead>
              <tbody>
                {fields.data.map((field) => (
                  <tr key={field.name}>
                    <td className="mono">{field.name}</td>
                    <td>
                      <span className="badge" data-kind={field.kind}>
                        {field.kind}
                      </span>
                    </td>
                    <td>{field.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>
    </>
  );
}
