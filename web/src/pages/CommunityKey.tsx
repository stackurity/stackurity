import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, ApiError, type CommunityKeyMeta } from "../api";
import { useAction } from "../hooks";
import { CopyBox, ErrorBox, Loading, Notice } from "../components/ui";
import { Challenge, safeLink } from "./Signup";

/**
 * /self-hosted-key on Stackurity Cloud: someone asking for the free key a
 * self-hosted server needs. Only the email, name and company are sent;
 * nothing about their servers.
 */
export function CommunityKeyPage({ meta }: { meta: CommunityKeyMeta }) {
  const [f, setF] = useState({ email: "", name: "", company: "" });
  const [accept, setAccept] = useState(false);
  const [token, setToken] = useState("");
  const [resetKey, setResetKey] = useState(0);
  const [localErr, setLocalErr] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const act = useAction();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    if (!accept) return setLocalErr("Please agree to the Terms of Service and the Privacy Policy.");
    if (!token) return setLocalErr("Please complete the check above the button first.");
    const email = f.email.trim();
    const r = await act.run(() =>
      api.requestCommunityKey({ email, name: f.name.trim(), company: f.company.trim(), turnstile_token: token, accept_terms: true }),
    );
    if (r) setSentTo(email);
    else setResetKey((k) => k + 1);
  };

  const emailRefused = act.error?.code === "email_not_accepted" ? act.error : null;
  const contact = safeLink(meta.contact_url ?? emailRefused?.details[0]);

  if (sentTo) {
    return (
      <div className="center-screen">
        <div className="auth-card auth-card-wide">
          <h1 className="auth-title">Check your email</h1>
          <p>
            We sent a link to <strong className="break">{sentTo}</strong>. Open it within 24 hours to see your key; we email the key as well.
          </p>
          <p className="small muted">
            Nothing arrived after a few minutes? Check your spam folder, or <a href="/self-hosted-key">ask again</a>.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="center-screen">
      <form className="auth-card auth-card-wide form" onSubmit={submit} aria-labelledby="ck-title">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={140} height={140} />
        </div>
        <h1 id="ck-title" className="auth-title">
          Get a free self-hosted key
        </h1>
        <p>
          Stackurity Community is free and open source (Apache-2.0). Each self-hosted server needs a free key, so we know who runs it and can tell you
          about security fixes. The key is checked on your server, offline: your server never contacts us for it.
        </p>
        <p className="small muted">
          We keep your email, name and company, and when the key was issued. Nothing about your servers or software is sent to us.
        </p>
        {!emailRefused && <ErrorBox error={act.error} title="That did not work" />}
        {localErr && (
          <div className="alert alert-error" role="alert">
            {localErr}
          </div>
        )}
        <div className="field">
          <label htmlFor="ck-email">Email</label>
          <input
            id="ck-email"
            type="email"
            required
            autoComplete="email"
            value={f.email}
            onChange={set("email")}
            autoFocus
            aria-invalid={emailRefused ? true : undefined}
            aria-describedby={emailRefused ? "ck-email-error" : undefined}
          />
          {emailRefused && (
            <p className="hint hint-error" id="ck-email-error" role="alert">
              {emailRefused.message}
              {contact && (
                <>
                  {" "}
                  <a href={contact} target="_blank" rel="noopener noreferrer">
                    Contact us
                  </a>
                </>
              )}
            </p>
          )}
        </div>
        <div className="field">
          <label htmlFor="ck-name">Your name</label>
          <input id="ck-name" required autoComplete="name" maxLength={200} value={f.name} onChange={set("name")} />
        </div>
        <div className="field">
          <label htmlFor="ck-company">Company (optional)</label>
          <input id="ck-company" autoComplete="organization" maxLength={100} value={f.company} onChange={set("company")} />
        </div>
        <label className="check-row">
          <input type="checkbox" checked={accept} onChange={(e) => setAccept(e.target.checked)} required />
          <span>
            I agree to the{" "}
            <a href={meta.terms_url} target="_blank" rel="noopener noreferrer">
              Terms of Service
            </a>{" "}
            and the{" "}
            <a href={meta.privacy_url} target="_blank" rel="noopener noreferrer">
              Privacy Policy
            </a>
            .
          </span>
        </label>
        <Challenge siteKey={meta.turnstile_site_key} onToken={setToken} resetKey={resetKey} />
        <button type="submit" className="btn btn-primary btn-block" disabled={act.pending}>
          {act.pending ? "Sending…" : "Email me a key"}
        </button>
      </form>
    </div>
  );
}

/**
 * /self-hosted-key/verify#<token>: the link from the email. The token stays
 * in the fragment and goes to the API in a request body only.
 */
export function VerifyCommunityKeyPage() {
  const [token] = useState(() => window.location.hash.replace(/^#/, "").trim());
  const [error, setError] = useState<ApiError | null>(null);
  const [key, setKey] = useState<{ key: string; email: string } | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (!token || started.current) return;
    started.current = true;
    api
      .verifyCommunityKey(token)
      .then((r) => {
        // Drop the link from the address bar and history.
        window.history.replaceState(null, "", "/self-hosted-key/verify");
        setKey(r);
      })
      .catch((e) => setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e))));
  }, [token]);

  let body;
  if (!token) {
    body = <Notice kind="warn">This page needs the whole link from the email. Open it again from the email.</Notice>;
  } else if (error) {
    body =
      error.status === 410 ? (
        <Notice kind="warn">
          This link does not work any more: it was already used, or it is more than 24 hours old. Your key was emailed when you first opened it;{" "}
          <a href="/self-hosted-key">ask again</a> for a new one.
        </Notice>
      ) : (
        <ErrorBox error={error} title="Could not issue the key" />
      );
  } else if (key) {
    body = (
      <>
        <p>
          Here is your free key. We also emailed it to <strong className="break">{key.email}</strong>.
        </p>
        <CopyBox value={key.key} label="Your key" />
        <ol className="steps small">
          <li>On your Stackurity server, sign in as an instance administrator.</li>
          <li>Paste the key where it is asked for (or under Instance &gt; Licence).</li>
        </ol>
        <p className="small muted">
          Servers without a dashboard: set STACKURITY_LICENSE (or STACKURITY_LICENSE_FILE) to the key, or run{" "}
          <code className="code">stackurity admin set-license</code>. The key is checked offline and does not expire.
        </p>
      </>
    );
  } else {
    body = <Loading label="Issuing your key…" />;
  }
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <h1 className="auth-title">Your free self-hosted key</h1>
        {body}
      </div>
    </div>
  );
}
