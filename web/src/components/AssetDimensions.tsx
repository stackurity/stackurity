import { Link } from "react-router";
import type { Dimension } from "../assetDimensions";
import { Badge } from "./Badge";

/**
 * Reporting, Coverage and Security side by side, each with its own name, so
 * "reporting normally" is never read as "secure" (assetDimensions.ts).
 */
export function AssetDimensions({ dims, securityTo }: { dims: Dimension[]; securityTo?: string }) {
  return (
    <span className="badges asset-dimensions" aria-label="Asset status">
      {dims.map((d) => {
        const badge = <Badge status={d.name.toLowerCase()} tone={d.tone} label={d.label} title={d.help} />;
        return (
          <span key={d.name} className="asset-dimension">
            <span className="small muted">{d.name}:</span> {d.name === "Security" && securityTo ? <Link to={securityTo}>{badge}</Link> : badge}
          </span>
        );
      })}
    </span>
  );
}
