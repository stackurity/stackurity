/**
 * The filters a list page has on, as removable chips (components/FilterChips.tsx).
 * Pages describe their query parameters once; the chips, removing one and
 * "Clear all" follow from the URL. Kept free of React so node --test can
 * load it (filterChips.test.ts).
 */

export interface FilterDef {
  /** The query parameter. */
  key: string;
  /** What the filter is, as the form labels it: "Kind", "Owner team". */
  label: string;
  /** How a value reads: an id to a team's name, "host" to "Host". */
  format?: (value: string) => string;
  /** A value that means "no filter" (Incidents' status is "open" unless set). */
  defaultValue?: string;
  /** A yes/no filter ("true" when on): the chip shows its label alone, "Reboot pending". */
  flag?: boolean;
}

export interface ActiveFilter {
  key: string;
  /** The chip's text: "Kind: host", or a flag's label. */
  text: string;
}

/** Parameters that are never a filter: paging. Removing a filter also goes back to the first page. */
const PAGING = ["offset"];

/** The chips for the filters on, in the order the page lists its filters. */
export function activeFilters(params: URLSearchParams, defs: FilterDef[]): ActiveFilter[] {
  const out: ActiveFilter[] = [];
  for (const d of defs) {
    const v = params.get(d.key);
    if (v === null || v === "" || v === d.defaultValue) continue;
    if (d.flag) {
      if (v !== "true") continue;
      out.push({ key: d.key, text: d.label });
      continue;
    }
    const shown = d.format ? d.format(v) : v;
    out.push({ key: d.key, text: `${d.label}: ${shown || v}` });
  }
  return out;
}

/** The URL without one filter, back on the first page. */
export function withoutFilter(params: URLSearchParams, key: string): URLSearchParams {
  const next = new URLSearchParams(params);
  next.delete(key);
  for (const p of PAGING) next.delete(p);
  return next;
}

/** The URL without any of the page's filters; other parameters (a tab) stay. */
export function withoutFilters(params: URLSearchParams, defs: FilterDef[]): URLSearchParams {
  let next = new URLSearchParams(params);
  for (const d of defs) next = withoutFilter(next, d.key);
  for (const p of PAGING) next.delete(p);
  return next;
}
