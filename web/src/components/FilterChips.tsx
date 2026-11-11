import type { ReactNode } from "react";
import type { ActiveFilter } from "../filterChips";
import { DensityControl } from "./Density";

/**
 * The filters on, each a chip with × to remove it, and Clear all. Shows
 * nothing when no filter is on. Build `filters` with activeFilters()
 * (filterChips.ts) from the page's query parameters.
 */
export function FilterChips({
  filters,
  onRemove,
  onClear,
}: {
  filters: ActiveFilter[];
  onRemove: (key: string) => void;
  onClear: () => void;
}) {
  if (filters.length === 0) return null;
  return (
    <div className="filter-chips" role="group" aria-label="Filters on">
      <span className="filter-chips-label small muted">Showing only:</span>
      <ul>
        {filters.map((f) => (
          <li key={f.key} className="filter-chip">
            <span>{f.text}</span>
            <button type="button" className="filter-chip-remove" aria-label={`Remove filter ${f.text}`} title="Remove this filter" onClick={() => onRemove(f.key)}>
              <span aria-hidden="true">×</span>
            </button>
          </li>
        ))}
      </ul>
      <button type="button" className="btn btn-sm btn-link" onClick={onClear}>
        Clear all
      </button>
    </div>
  );
}

/**
 * The line between a list page's filters and its table: the filters on (as
 * chips) on the left, the row-spacing control on the right.
 */
export function TableToolbar({ children }: { children?: ReactNode }) {
  return (
    <div className="table-toolbar">
      <div className="table-toolbar-main">{children}</div>
      <DensityControl />
    </div>
  );
}
