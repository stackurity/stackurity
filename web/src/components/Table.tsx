import { useEffect, useRef, useState, type ReactNode } from "react";

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
 *
 * A last column with the key "actions" (the row's buttons) is pinned to the
 * right edge, so its controls are never cut off. While columns are hidden
 * to one side, that edge shows a shadow and a line under the table says the
 * table scrolls sideways.
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
  const wrap = useRef<HTMLDivElement>(null);
  const [hidden, setHidden] = useState({ left: false, right: false });
  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const check = () => {
      const left = el.scrollLeft > 1;
      const right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
      setHidden((h) => (h.left === left && h.right === right ? h : { left, right }));
    };
    check();
    el.addEventListener("scroll", check, { passive: true });
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(check);
    ro?.observe(el);
    if (el.firstElementChild) ro?.observe(el.firstElementChild);
    return () => {
      el.removeEventListener("scroll", check);
      ro?.disconnect();
    };
  }, []);
  const pinEnd = columns.length > 1 && columns[columns.length - 1].key === "actions";
  const wrapCls = ["table-wrap", hidden.left ? "more-left" : "", hidden.right ? "more-right" : ""].filter(Boolean).join(" ");
  const tableCls = ["table", stickyFirst ? "table-sticky-first" : "", pinEnd ? "table-sticky-end" : ""].filter(Boolean).join(" ");
  return (
    <>
    {/* Above the table, so a long table's cue is seen before scrolling down to its end. */}
    {(hidden.left || hidden.right) && (
      <p className="table-more small muted" aria-hidden="true">
        {hidden.right ? "More columns to the right: scroll the table sideways →" : "← Scroll the table back for the first columns"}
      </p>
    )}
    <div ref={wrap} className={wrapCls} tabIndex={0} role="region" aria-label={caption ?? "Table"}>
      <table className={tableCls}>
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
    </>
  );
}
