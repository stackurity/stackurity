import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { api, ApiError, type PagerDutyFinishResult, type PagerDutyOAuthResult, type PagerDutyService } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Loading, Notice } from "../components/ui";
import { errorView } from "../errors";

/*
 * /integrations/pagerduty/oauth/callback?code=…&state=…: PagerDuty sends the
 * browser here after "Connect PagerDuty". The state works once, so the
 * exchange runs once per state even when React runs effects twice
 * (StrictMode). Then the admin picks the service; Stackurity adds the
 * integration to it, keeps its key, and forgets PagerDuty's token.
 */

const START_AGAIN = "/settings/integrations/new/pagerduty";

const exchanges = new Map<string, Promise<PagerDutyOAuthResult>>();

/** Only addresses inside the dashboard. */
function safeReturn(to: string | undefined, fallback: string): string {
  return to && to.startsWith("/") && !to.startsWith("//") ? to : fallback;
}

function withChannel(to: string, id: number): string {
  const u = new URL(to, window.location.origin);
  u.searchParams.set("channel", String(id));
  return u.pathname + u.search;
}

const asApiError = (e: unknown) => (e instanceof ApiError ? e : new ApiError(0, "client", String(e)));

export function PagerDutyOAuthCallbackPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [q] = useState(() => new URLSearchParams(window.location.search));
  const code = q.get("code") ?? "";
  const state = q.get("state") ?? "";
  const denied = q.get("error");
  const admin = can("admin");
  const [error, setError] = useState<ApiError | null>(null);
  const [conn, setConn] = useState<PagerDutyOAuthResult | null>(null);
  const [services, setServices] = useState<PagerDutyService[]>([]);
  const [more, setMore] = useState(false);
  const [filter, setFilter] = useState("");
  const [picked, setPicked] = useState("");
  const [busy, setBusy] = useState(false);
  const [finishError, setFinishError] = useState<ApiError | null>(null);
  const [searchError, setSearchError] = useState<ApiError | null>(null);

  useEffect(() => {
    if (denied || !code || !state || !admin) return;
    let p = exchanges.get(state);
    if (!p) {
      p = api.post<PagerDutyOAuthResult>("/integrations/pagerduty/oauth", { code, state });
      exchanges.set(state, p);
    }
    let live = true;
    p.then((r) => {
      if (!live) return;
      setConn(r);
      setServices(r.services ?? []);
      setMore(r.more);
      if (r.services?.length === 1) setPicked(r.services[0].id);
    }).catch((e) => {
      if (live) setError(asApiError(e));
    });
    return () => {
      live = false;
    };
  }, [code, state, denied, admin]);

  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return f ? services.filter((s) => s.name.toLowerCase().includes(f) || s.id.toLowerCase() === f) : services;
  }, [services, filter]);

  // Large accounts: ask PagerDuty with the filter as a query.
  const search = async (e: FormEvent) => {
    e.preventDefault();
    if (!conn || !more) return;
    setSearchError(null);
    setBusy(true);
    try {
      const r = await api.post<{ services: PagerDutyService[]; more: boolean }>("/integrations/pagerduty/services", { session: conn.session, query: filter.trim() });
      setServices(r.services ?? []);
      setMore(r.more);
    } catch (err) {
      setSearchError(asApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const finish = async () => {
    if (!conn || !picked) return;
    setFinishError(null);
    setBusy(true);
    try {
      const r = await api.post<PagerDutyFinishResult>("/integrations/pagerduty/finish", { session: conn.session, service_id: picked });
      navigate(withChannel(safeReturn(r.return_to, "/settings/integrations"), r.channel.id), { replace: true });
    } catch (err) {
      setFinishError(asApiError(err));
      setBusy(false);
    }
  };

  const cancel = async () => {
    setBusy(true);
    if (conn) await api.post("/integrations/pagerduty/cancel", { session: conn.session }).catch(() => undefined);
    navigate(safeReturn(conn?.return_to, "/settings/integrations"), { replace: true });
  };

  const startAgain = (label: string) => (
    <div className="slack-link-actions">
      <Link className="btn btn-primary btn-block" to={START_AGAIN}>
        {label}
      </Link>
      <Link className="btn btn-block" to="/settings/integrations">
        Back to integrations
      </Link>
    </div>
  );

  let title = "Connect PagerDuty";
  let body: ReactNode;
  if (denied) {
    body = (
      <>
        <Notice kind="info">
          {denied === "access_denied"
            ? "You cancelled on PagerDuty's page, so nothing was connected."
            : `PagerDuty did not finish connecting Stackurity (${denied}). Nothing was connected.`}
        </Notice>
        {startAgain("Try again")}
      </>
    );
  } else if (!code || !state) {
    body = (
      <>
        <Notice kind="warn">This page needs the whole address PagerDuty sent you back to. Nothing was connected.</Notice>
        {startAgain("Start again")}
      </>
    );
  } else if (!admin) {
    body = <Notice kind="warn">Only administrators can connect PagerDuty. Ask one to do it.</Notice>;
  } else if (error) {
    body = (
      <>
        {error.status === 400 ? (
          <Notice kind="warn">
            This Connect PagerDuty request cannot be used: it was started by someone else or in another organisation, it was already used, or it is more than 10
            minutes old. Nothing was connected.
          </Notice>
        ) : error.status === 502 ? (
          <Notice kind="warn">{errorView(error).text}</Notice>
        ) : (
          <ErrorBox error={error} title="Could not connect PagerDuty" />
        )}
        {startAgain("Start again")}
      </>
    );
  } else if (finishError) {
    title = "PagerDuty refused";
    body = (
      <>
        {finishError.status === 400 ? (
          <Notice kind="warn">This choice took more than 10 minutes or was already made. Nothing was added.</Notice>
        ) : (
          <Notice kind="warn">{errorView(finishError).text} Nothing was added; Stackurity no longer holds the PagerDuty sign-in, so start again to pick another service.</Notice>
        )}
        {startAgain("Start again")}
      </>
    );
  } else if (conn) {
    title = "Pick the PagerDuty service";
    body = (
      <>
        <p>
          Stackurity adds an <strong>Events API V2</strong> integration named <strong>Stackurity</strong> to the service you pick, and pages through it.
          {conn.region === "eu" ? " Your account is in PagerDuty's EU service region." : ""}
        </p>
        {services.length === 0 && !more && !filter ? (
          <Notice kind="warn">
            This PagerDuty account has no services you can see. Create one in PagerDuty (it needs an escalation policy), then start again.
          </Notice>
        ) : (
          <form className="form" onSubmit={(e) => void search(e)}>
            <div className="field">
              <label htmlFor="pd-filter">Find a service</label>
              <input id="pd-filter" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Service name" autoComplete="off" />
              {more && <p className="hint">Only the first 1,000 services are listed. Type part of the name and press Enter to search PagerDuty.</p>}
            </div>
            <ErrorBox error={searchError} title="Could not search PagerDuty" />
            <fieldset className="field">
              <legend>Service</legend>
              <div className="pd-services" role="radiogroup">
                {shown.slice(0, 200).map((s) => (
                  <label key={s.id} className="check">
                    <input type="radio" name="pd-service" value={s.id} checked={picked === s.id} onChange={() => setPicked(s.id)} />
                    <span>
                      {s.name} <span className="muted mono small">{s.id}</span>
                      {s.status === "disabled" && <span className="muted small"> (disabled)</span>}
                    </span>
                  </label>
                ))}
                {shown.length === 0 && <p className="muted">No service matches.</p>}
                {shown.length > 200 && <p className="hint">{shown.length - 200} more: type part of the name.</p>}
              </div>
            </fieldset>
          </form>
        )}
        <p className="hint">Your PagerDuty user must be allowed to add integrations to the service (an admin, or the service's manager).</p>
        <div className="slack-link-actions">
          <button type="button" className="btn btn-primary btn-block" onClick={() => void finish()} disabled={!picked || busy}>
            {busy ? "Connecting…" : "Add the Stackurity integration"}
          </button>
          <button type="button" className="btn btn-block" onClick={() => void cancel()} disabled={busy}>
            Cancel
          </button>
        </div>
      </>
    );
  } else {
    body = <Loading label="Connecting PagerDuty…" />;
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">{title}</h1>
        {body}
      </div>
    </div>
  );
}
