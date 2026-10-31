import { sparkPoints } from "../dashboard";

const W = 220;
const H = 44;

function shortDay(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

/**
 * A single-series trend: a 2px line in the de-emphasis ink with today's
 * point in the accent. Each point has a hover title, and the values are in
 * a visually hidden table for screen readers.
 */
export function Sparkline({ values, days, label }: { values: number[]; days: string[]; label: string }) {
  const pts = sparkPoints(values, W, H);
  if (pts.length === 0) return null;
  const last = pts[pts.length - 1];
  return (
    <figure className="spark">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={label} className="spark-svg">
        <polyline className="spark-line" points={pts.map((p) => p.join(",")).join(" ")} vectorEffect="non-scaling-stroke" />
        {pts.map((p, i) => (
          <circle key={i} className="spark-hit" cx={p[0]} cy={p[1]} r={6}>
            <title>{`${shortDay(days[i])}: ${values[i].toLocaleString()} open`}</title>
          </circle>
        ))}
        <circle className="spark-now" cx={last[0]} cy={last[1]} r={3.5} vectorEffect="non-scaling-stroke" />
      </svg>
      <table className="sr-only">
        <caption>{label}</caption>
        <tbody>
          {values.map((v, i) => (
            <tr key={i}>
              <th scope="row">{shortDay(days[i])}</th>
              <td>{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}

/** Fixes per week as four thin columns from the baseline, each labelled with its count. */
export function WeekBars({ weeks }: { weeks: { start: string; end: string; fixed: number }[] }) {
  const hi = Math.max(1, ...weeks.map((w) => w.fixed));
  return (
    <ol className="weekbars" aria-label="Issues fixed per week">
      {weeks.map((w) => (
        <li key={w.start} className="weekbar" title={`${shortDay(w.start)} to ${shortDay(w.end)}: ${w.fixed.toLocaleString()} fixed`}>
          <span className="weekbar-value" aria-hidden="true">{w.fixed.toLocaleString()}</span>
          <span className="weekbar-track">
            <span className="weekbar-fill" style={{ height: `${Math.max((w.fixed / hi) * 100, w.fixed > 0 ? 6 : 0)}%` }} />
          </span>
          <span className="weekbar-label" aria-hidden="true">{shortDay(w.end)}</span>
          <span className="sr-only">
            {" "}
            week to {shortDay(w.end)}: {w.fixed} fixed
          </span>
        </li>
      ))}
    </ol>
  );
}
