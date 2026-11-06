import type { ReactNode } from "react";

export interface Column<T> {
  key: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  className?: string;
  /** Right-align numeric columns. */
  numeric?: boolean;
}

/**
 * A semantic, dense data table. Rows may be selectable (onRowClick); the row
 * is then keyboard-focusable and responds to Enter/Space.
 *
 * A table wider than the page scrolls sideways inside its own box
 * (.table-wrap), never the page, and its first column (what the row is)
 * stays in view while it does. Pass stickyFirst={false} when the first
 * column does not say what the row is.
 */
export function Table<T>({
  columns,
  rows,
  rowKey,
  caption,
  onRowClick,
  selectedKey,
  rowClassName,
  renderExpanded,
  stickyFirst = true,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string | number;
  caption?: string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | number | null;
  rowClassName?: (row: T) => string | undefined;
  /** Rendered in a full-width row under the selected row. */
  renderExpanded?: (row: T) => ReactNode;
  /** Keep the first column in view while the table scrolls sideways (default). */
  stickyFirst?: boolean;
}) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label={caption ?? "Table"}>
      <table className={stickyFirst ? "table table-sticky-first" : "table"}>
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col" className={[c.className, c.numeric ? "num" : ""].filter(Boolean).join(" ") || undefined}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const k = rowKey(r);
            const selected = selectedKey !== undefined && selectedKey === k;
            const cls = [onRowClick ? "clickable" : "", selected ? "selected" : "", rowClassName?.(r) ?? ""]
              .filter(Boolean)
              .join(" ");
            return [
              <tr
                key={k}
                className={cls || undefined}
                tabIndex={onRowClick ? 0 : undefined}
                aria-expanded={onRowClick && renderExpanded ? selected : undefined}
                onClick={onRowClick ? () => onRowClick(r) : undefined}
                onKeyDown={
                  onRowClick
                    ? (e) => {
                        if (e.target !== e.currentTarget) return;
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          onRowClick(r);
                        }
                      }
                    : undefined
                }
              >
                {columns.map((c) => (
                  <td key={c.key} className={[c.className, c.numeric ? "num" : ""].filter(Boolean).join(" ") || undefined}>
                    {c.cell(r)}
                  </td>
                ))}
              </tr>,
              selected && renderExpanded ? (
                <tr key={`${k}-expanded`} className="expanded">
                  <td colSpan={columns.length}>{renderExpanded(r)}</td>
                </tr>
              ) : null,
            ];
          })}
        </tbody>
      </table>
    </div>
  );
}
