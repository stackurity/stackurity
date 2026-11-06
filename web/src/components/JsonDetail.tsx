import { jsonEmpty, jsonSummary } from "../jsonSummary";

/**
 * A JSON value in a table cell: a short one-line summary that opens to the
 * whole value, formatted. Used by the audit log and Jobs.
 */
export function JsonDetail({ value, label = "Show the full detail" }: { value: unknown; label?: string }) {
  if (jsonEmpty(value)) return <span className="muted">—</span>;
  return (
    <details className="json">
      <summary className="small" title={label}>
        <span className="json-summary">{jsonSummary(value)}</span>
      </summary>
      <pre className="mono small">{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}
