/**
 * Row density for data tables (components/Table.tsx), remembered per viewer
 * in this browser. Only row padding and font size change (styles/ui-polish.css);
 * "default" is the table as it always was. Kept free of React so node --test
 * can load it (tableDensity.test.ts).
 */

export type Density = "comfortable" | "default" | "compact";

export const DENSITIES: { value: Density; label: string; hint: string }[] = [
  { value: "comfortable", label: "Comfortable", hint: "More space between rows" },
  { value: "default", label: "Default", hint: "The usual spacing" },
  { value: "compact", label: "Compact", hint: "More rows on screen" },
];

export const DENSITY_KEY = "stackurity.tableDensity";

/** A stored value, or "default" for anything else (missing, old, edited by hand). */
export function parseDensity(v: unknown): Density {
  return v === "comfortable" || v === "compact" ? v : "default";
}

/** The subset of Storage used here, so tests can pass a fake. */
export interface DensityStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** The viewer's choice. Storage can be missing or throw (private windows, blocked site data). */
export function readDensity(storage: DensityStorage | null | undefined): Density {
  try {
    return parseDensity(storage?.getItem(DENSITY_KEY));
  } catch {
    return "default";
  }
}

/** Remembers the choice; "default" removes the key. Returns false when it could not be stored. */
export function writeDensity(storage: DensityStorage | null | undefined, d: Density): boolean {
  if (!storage) return false;
  try {
    if (d === "default") storage.removeItem(DENSITY_KEY);
    else storage.setItem(DENSITY_KEY, d);
    return true;
  } catch {
    return false;
  }
}

/** The class Table adds to its box: none for default, so default looks exactly as before. */
export function densityClass(d: Density): string {
  return d === "default" ? "" : `density-${d}`;
}

function browserStorage(): DensityStorage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

// One value for the page, so every table and every control agree (useSyncExternalStore).
let current: Density | null = null;
const listeners = new Set<() => void>();

export function getDensity(): Density {
  if (current === null) current = readDensity(browserStorage());
  return current;
}

export function setDensity(d: Density): void {
  current = d;
  writeDensity(browserStorage(), d);
  for (const l of listeners) l();
}

export function subscribeDensity(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}
