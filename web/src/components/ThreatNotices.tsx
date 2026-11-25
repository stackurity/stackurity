import { useState } from "react";
import { Link } from "react-router";
import { api, type ThreatNotice } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { bannerNotices, noticeTone } from "../threatNotices";

/**
 * Threat notices (docs/threat-notices.md): when a new attack, attacker tool
 * or exploited vulnerability appears, the organisation's administrators and
 * security team see what it means for them, with one button (see findings,
 * connect, upgrade). Each person can hide a notice; it shows again if the
 * threat is later found on the organisation's assets.
 */
export function ThreatNoticeBanner({ workspaceId }: { workspaceId: number }) {
  const { can } = useAuth();
  const allowed = can("security");
  const res = useLoad(
    () => (allowed ? api.getAll<{ items: ThreatNotice[] }>("/threat-notices").catch(() => null) : Promise.resolve(null)),
    [allowed, workspaceId],
  );
  // Hidden in memory at once; the server keeps it hidden from then on.
  const [hidden, setHidden] = useState<number[]>([]);
  const shown = bannerNotices(res.data?.items ?? []).filter((n) => !hidden.includes(n.id));
  if (!allowed || shown.length === 0) return null;
  return (
    <>
      {shown.map((n) => (
        <div
          key={n.id}
          className={`alert alert-${noticeTone(n.verdict, n.kind)} update-banner threat-banner`}
          role={n.verdict === "found" ? "alert" : "status"}
        >
          <span className="update-banner-text">
            <strong>{n.title}.</strong> {n.lines.slice(0, 2).join(" ")}{" "}
            <Link to="/help/threat-notices">What is a threat notice?</Link>
          </span>
          {n.action &&
            (n.action.link.startsWith("https://") ? (
              <a className="btn btn-sm btn-primary" href={n.action.link} target="_blank" rel="noreferrer">
                {n.action.label}
              </a>
            ) : (
              <Link className="btn btn-sm btn-primary" to={n.action.link}>
                {n.action.label}
              </Link>
            ))}
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              setHidden((h) => [...h, n.id]);
              void api.post(`/threat-notices/${n.id}/dismiss`).catch(() => {
                // Not stored: it shows again on the next page load.
              });
            }}
          >
            Dismiss<span className="sr-only"> the notice about {n.name}</span>
          </button>
        </div>
      ))}
    </>
  );
}
