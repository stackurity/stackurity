import { api, type CommunityKeyRegistration } from "../../api";
import { useLoad } from "../../hooks";
import { Table, type Column } from "../../components/Table";
import { Card, EmptyState, ErrorBox, Loading, PageHeader, RelativeTime } from "../../components/ui";

interface Registrations {
  /** Keys issued, and distinct emails they went to. */
  total: number;
  emails: number;
  last_30_days: number;
  items: CommunityKeyRegistration[];
}

/** Instance administration on Stackurity Cloud: the free self-hosted keys issued. */
export function CommunityKeysPage() {
  const res = useLoad(() => api.get<Registrations>("/admin/community-keys", { limit: 500 }), []);
  const d = res.data;
  const columns: Column<CommunityKeyRegistration>[] = [
    { key: "email", header: "Email", cell: (r) => <span className="break">{r.email}</span> },
    { key: "name", header: "Name", cell: (r) => r.name },
    { key: "company", header: "Company", cell: (r) => r.company || <span className="muted">none</span> },
    { key: "issued", header: "Issued", cell: (r) => <RelativeTime iso={r.issued_at} /> },
    { key: "id", header: "Key id", cell: (r) => <span className="mono small">{r.key_id}</span> },
  ];
  return (
    <>
      <PageHeader title="Self-hosted keys" sub="Free keys issued to people who self-host Stackurity Community, newest first." />
      <ErrorBox error={res.error} title="Could not load the keys" />
      {!d && !res.error && <Loading />}
      {d && (
        <>
          <Card>
            <p>
              {d.total} keys issued to {d.emails} email addresses; {d.last_30_days} in the last 30 days.
            </p>
          </Card>
          {d.items.length === 0 ? (
            <EmptyState title="No keys issued yet" />
          ) : (
            <Table columns={columns} rows={d.items} rowKey={(r) => r.id} caption="Self-hosted keys" />
          )}
        </>
      )}
    </>
  );
}
