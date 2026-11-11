/**
 * Grey placeholders in the shape of what is loading, instead of a "Loading…"
 * line that makes the page jump when the table arrives. The shimmer stops for
 * people who ask for less motion (styles/ui-polish.css). Screen readers hear
 * the label once. Bar widths vary by row in the CSS, so the placeholder reads
 * as text, not a grid.
 */

export function TableSkeleton({ rows = 6, columns = 5, label = "Loading…" }: { rows?: number; columns?: number; label?: string }) {
  return (
    <div className="skeleton-table table-wrap" role="status" aria-busy="true">
      <span className="sr-only">{label}</span>
      <table className="table" aria-hidden="true">
        <thead>
          <tr>
            {Array.from({ length: columns }, (_, c) => (
              <th key={c}>
                <span className="skeleton-bar" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }, (_, r) => (
            <tr key={r}>
              {Array.from({ length: columns }, (_, c) => (
                <td key={c}>
                  <span className="skeleton-bar" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Placeholder cards for a list of cards (approvals, rules). */
export function CardSkeleton({ count = 3, lines = 2, label = "Loading…" }: { count?: number; lines?: number; label?: string }) {
  return (
    <div className="skeleton-cards" role="status" aria-busy="true">
      <span className="sr-only">{label}</span>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="skeleton-card" aria-hidden="true">
          <span className="skeleton-bar skeleton-title" />
          {Array.from({ length: lines }, (_, l) => (
            <span key={l} className="skeleton-bar" />
          ))}
        </div>
      ))}
    </div>
  );
}
