import { useEffect, useRef, useState } from "react";
import { api, type Channel, type TeamsInstallStart, type TeamsInstallStatus } from "../api";
import { useAction } from "../hooks";
import { CopyBox, ErrorBox } from "./ui";

/*
 * "Add to Teams" (the Stackurity Teams app). Teams cannot carry anything of
 * ours through its install, so the channel is bound with a code: the server
 * makes one for this person (single use, 15 minutes), they add the app to a
 * team in Teams and send the code to it in the channel that should get the
 * notifications. This page asks every few seconds whether that happened,
 * then opens the new integration.
 */

const POLL_MS = 3000;

export function AddToTeams({
  onConnected,
  startPath = "/integrations/teams/install",
}: {
  onConnected: (c: Channel) => void;
  /** Where the code is made: a project's Add to Teams makes the project's channel. */
  startPath?: string;
}) {
  const act = useAction();
  const [start, setStart] = useState<TeamsInstallStart | null>(null);
  const [status, setStatus] = useState<TeamsInstallStatus["status"]>("pending");
  const connected = useRef(onConnected);
  connected.current = onConnected;

  const begin = async () => {
    const r = await act.run(() => api.post<TeamsInstallStart>(startPath, {}));
    if (r) {
      setStatus("pending");
      setStart(r);
    }
  };

  useEffect(() => {
    if (!start) return;
    let live = true;
    let timer = 0;
    const tick = async () => {
      try {
        const s = await api.get<TeamsInstallStatus>(`/integrations/teams/install/${start.id}`);
        if (!live) return;
        setStatus(s.status);
        if (s.status === "connected" && s.channel) {
          connected.current(s.channel);
          return;
        }
        if (s.status !== "pending") return;
      } catch {
        /* a failed check is tried again */
      }
      if (live) timer = window.setTimeout(() => void tick(), POLL_MS);
    };
    timer = window.setTimeout(() => void tick(), POLL_MS);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [start]);

  if (!start)
    return (
      <>
        <p>
          Add the Stackurity app to a team in Microsoft Teams, then send it a code in the channel that should get the notifications. Nothing to copy from
          Teams, no webhook.
        </p>
        <ErrorBox error={act.error} title="Could not start Add to Teams" />
        <div>
          <button type="button" className="btn btn-primary" onClick={() => void begin()} disabled={act.pending}>
            {act.pending ? "Starting…" : "Add to Teams"}
          </button>
        </div>
      </>
    );

  const message = `@Stackurity ${start.code}`;
  return (
    <div className="teams-install">
      <ol>
        <li>
          <a className="btn btn-primary" href={start.install_url} target="_blank" rel="noreferrer">
            Open Stackurity in Teams
          </a>{" "}
          and click <strong>Add to a team</strong>. Pick the team and the channel for the notifications.
        </li>
        <li>
          In that channel, send this message (type <strong>@Stackurity</strong> and pick the app, then the code):
          <CopyBox value={message} label="Message to send in Teams" />
          The code works once, for 15 minutes, and only for you.
        </li>
      </ol>
      <p role="status" className="small">
        {status === "pending" && "Waiting for the code in Teams…"}
        {status === "connected" && "Connected. Opening the integration…"}
        {(status === "expired" || status === "failed") && (
          <>
            {status === "expired" ? "The code expired." : "The code was used, but the channel could not be added."}{" "}
            <button type="button" className="btn btn-link btn-inline" onClick={() => void begin()} disabled={act.pending}>
              Get a new code
            </button>
          </>
        )}
      </p>
    </div>
  );
}
