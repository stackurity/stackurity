import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { api, ApiError, SLACK_PENDING_KEY, type SlackOAuthResult, type SlackPendingRoute } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Loading, Notice } from "../components/ui";

/*
 * /integrations/slack/oauth/callback?code=…&state=…: Slack sends the browser
 * here after "Add to Slack". The state works once, so the exchange runs once
 * per state even when React runs effects twice (StrictMode).
 */

type Outcome = { result: SlackOAuthResult; routeError: ApiError | null };

const exchanges = new Map<string, Promise<Outcome>>();

function readPending(): SlackPendingRoute | null {
  try {
    const raw = window.sessionStorage.getItem(SLACK_PENDING_KEY);
    return raw ? (JSON.parse(raw) as SlackPendingRoute) : null;
  } catch {
    return null;
  }
}

function dropPending() {
  try {
    window.sessionStorage.removeItem(SLACK_PENDING_KEY);
  } catch {
    /* storage blocked */
  }
}

/** Only addresses inside the dashboard. */
function safeReturn(to: string | undefined, fallback: string): string {
  return to && to.startsWith("/") && !to.startsWith("//") ? to : fallback;
}

function withChannel(to: string, id: number): string {
  const u = new URL(to, window.location.origin);
  u.searchParams.set("channel", String(id));
  return u.pathname + u.search;
}

async function exchange(code: string, state: string): Promise<Outcome> {
  const result = await api.post<SlackOAuthResult>("/integrations/slack/oauth", { code, state });
  let routeError: ApiError | null = null;
  const pending = readPending();
  // Onboarding saved what to send before going to Slack: add that route now.
  if (pending && safeReturn(result.return_to, "").startsWith("/get-started")) {
    try {
      await api.post("/routes", {
        name: pending.route_name,
        channel_id: result.channel.id,
        enabled: true,
        project_ids: [pending.project_id],
        events: pending.events,
        new_min_priority: pending.new_min_priority,
        min_priority: "P1",
        escalation: pending.escalation,
        summary_time: pending.summary_time,
        summary_day: pending.summary_day,
        timezone: pending.timezone,
        max_per_hour: pending.max_per_hour,
        send_resolved: pending.send_resolved,
      });
    } catch (e) {
      routeError = e instanceof ApiError ? e : new ApiError(0, "client", String(e));
    }
  }
  dropPending();
  return { result, routeError };
}

export function SlackOAuthCallbackPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [q] = useState(() => new URLSearchParams(window.location.search));
  const code = q.get("code") ?? "";
  const state = q.get("state") ?? "";
  const denied = q.get("error");
  const [error, setError] = useState<ApiError | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const admin = can("admin");
  const fromOnboarding = readPending() !== null;
  const backTo = fromOnboarding ? "/get-started?step=notify" : "/settings/integrations";

  useEffect(() => {
    if (denied || !code || !state || !admin) return;
    let p = exchanges.get(state);
    if (!p) {
      p = exchange(code, state);
      exchanges.set(state, p);
    }
    let live = true;
    p.then((o) => {
      if (!live) return;
      if (o.routeError) {
        setOutcome(o);
        return;
      }
      navigate(withChannel(safeReturn(o.result.return_to, "/settings/integrations"), o.result.channel.id), { replace: true });
    }).catch((e) => {
      if (live) setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    });
    return () => {
      live = false;
    };
  }, [code, state, denied, admin, navigate]);

  useEffect(() => {
    if (denied) dropPending();
  }, [denied]);

  let body: ReactNode;
  if (!admin) {
    body = <Notice kind="warn">Only administrators can connect Slack. Ask one to do it.</Notice>;
  } else if (denied) {
    body = (
      <>
        <Notice kind="info">Slack was not connected{denied === "access_denied" ? ": it was cancelled in Slack." : "."}</Notice>
        <p>
          <Link to={backTo}>Go back</Link>
        </p>
      </>
    );
  } else if (!code || !state) {
    body = (
      <>
        <Notice kind="warn">This page needs the whole address Slack sent you back to. Start again with Add to Slack.</Notice>
        <p>
          <Link to={backTo}>Go back</Link>
        </p>
      </>
    );
  } else if (error) {
    body = (
      <>
        {error.status === 400 ? (
          <Notice kind="warn">This link from Slack does not work any more (it is used or too old). Start again with Add to Slack.</Notice>
        ) : error.status === 502 ? (
          <Notice kind="warn">Slack refused the connection: {error.message}</Notice>
        ) : (
          <ErrorBox error={error} title="Could not connect Slack" />
        )}
        <div className="form-actions">
          <Link className="btn btn-primary" to={backTo}>
            Try again
          </Link>
        </div>
      </>
    );
  } else if (outcome) {
    const r = outcome.result;
    body = (
      <>
        <Notice kind="success">
          Slack is connected: {r.slack_channel} in {r.team_name}.
        </Notice>
        <ErrorBox error={outcome.routeError} title="Could not choose what to send" />
        <p>Choose what this channel hears about in its settings.</p>
        <div className="form-actions">
          <Link className="btn btn-primary" to={`/settings/integrations/channels/${r.channel.id}`}>
            Choose what to send
          </Link>
        </div>
      </>
    );
  } else {
    body = <Loading label="Connecting Slack…" />;
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">Add to Slack</h1>
        {body}
      </div>
    </div>
  );
}
