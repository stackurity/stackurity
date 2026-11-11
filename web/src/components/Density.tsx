import { useSyncExternalStore } from "react";
import { DENSITIES, getDensity, setDensity, subscribeDensity, type Density } from "../tableDensity";

/** The viewer's table density, the same in every table on the page. */
export function useTableDensity(): Density {
  return useSyncExternalStore(subscribeDensity, getDensity, () => "default" as Density);
}

/**
 * Comfortable / Default / Compact for the tables on a list page, remembered
 * in this browser. It changes row spacing and text size only.
 */
export function DensityControl() {
  const density = useTableDensity();
  return (
    <div className="density-control" role="group" aria-label="Table row spacing">
      <span className="density-label small muted" aria-hidden="true">
        Rows
      </span>
      {DENSITIES.map((d) => (
        <button
          key={d.value}
          type="button"
          className={`density-option${density === d.value ? " active" : ""}`}
          aria-pressed={density === d.value}
          title={d.hint}
          onClick={() => setDensity(d.value)}
        >
          {d.label}
        </button>
      ))}
    </div>
  );
}
