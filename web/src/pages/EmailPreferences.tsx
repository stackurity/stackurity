import { useEffect, useState, type ReactNode } from "react";
import { api, ApiError, type EmailCategory, type EmailPreferences, type EmailPreferencesChange } from "../api";
import { ErrorBox, Loading, Notice } from "../components/ui";

/** The two categories as toggles. */
function CategoryToggles({
  prefs,
  onChange,
  pending,
}: {
  prefs: EmailPreferences;
  onChange: (c: EmailPreferencesChange) => void;
  pending: boolean;
}) {
  return (
    <ul className="plain-list email-prefs">
      {prefs.categories.map((c) => (
        <li key={c.category}>
          <label className="check-row">
            <input
              type="checkbox"
              role="switch"
              checked={c.subscribed}
              disabled={pending}
              onChange={(e) => onChange({ [c.category]: e.target.checked })}
              aria-describedby={`email-pref-${c.category}`}
            />
            <span>
              <strong>{c.label}</strong>
              <span className="hint" id={`email-pref-${c.category}`}>
                {c.description}
              </span>
            </span>
          </label>
        </li>
      ))}
    </ul>
  );
}

/** Email that cannot be turned off, and why. */
function LockedCategories({ prefs }: { prefs: EmailPreferences }) {
  return (
    <>
      <h3 className="email-prefs-locked-title">Always sent</h3>
      <p className="hint">These are about your account and your organisation, so you get them whatever you choose above.</p>
      <ul className="plain-list email-prefs">
        {prefs.locked.map((l) => (
          <li key={l.label}>
            <label className="check-row">
              <input type="checkbox" checked disabled aria-describedby={`email-locked-${l.label}`} />
              <span>
                <strong>{l.label}</strong>
                <span className="hint" id={`email-locked-${l.label}`}>
                  {l.description}
                </span>
              </span>
            </label>
          </li>
        ))}
      </ul>
    </>
  );
}

/** Your account → Email preferences, for the signed-in person. */
export function MyEmailPreferences() {
  const [prefs, setPrefs] = useState<EmailPreferences | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [pending, setPending] = useState(false);

  useEffect(() => {
    api
      .myEmailPreferences()
      .then(setPrefs)
      .catch((e) => setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e))));
  }, []);

  const change = async (c: EmailPreferencesChange) => {
    setPending(true);
    setError(null);
    try {
      setPrefs(await api.setMyEmailPreferences(c));
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    } finally {
      setPending(false);
    }
  };

  return (
    <section id="email" className="card">
      <header className="card-head">
        <h2>Email preferences</h2>
      </header>
      <p className="hint">Choose which emails from Stackurity you get. A change applies at once, including to an email already being sent.</p>
      <ErrorBox error={error} title="Could not save" />
      {!prefs && !error && <Loading label="Loading…" />}
      {prefs && (
        <>
          <CategoryToggles prefs={prefs} onChange={change} pending={pending} />
          <LockedCategories prefs={prefs} />
        </>
      )}
    </section>
  );
}

const LABEL: Record<EmailCategory, string> = { marketing: "Marketing", vulnerability_news: "Vulnerability news" };

/*
 * /email/preferences#<token>: the links in product update and
 * vulnerability news emails, signed in or not. An unsubscribe link (one
 * category) shows one button; an Email preferences link shows both
 * toggles. The token stays in the fragment, which browsers never send to a
 * server, and goes to the API in a request body only. Nothing changes until
 * the person presses something, so mail scanners that open links change
 * nothing.
 */
export function EmailPreferencesPage() {
  const [token] = useState(() => window.location.hash.replace(/^#/, "").trim());
  const [prefs, setPrefs] = useState<EmailPreferences | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [pending, setPending] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!token) return;
    api
      .linkEmailPreferences(token)
      .then(setPrefs)
      .catch((e) => setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e))));
  }, [token]);

  const change = async (c: EmailPreferencesChange) => {
    setPending(true);
    setError(null);
    try {
      setPrefs(await api.updateLinkEmailPreferences(token, c));
      setSaved(true);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    } finally {
      setPending(false);
    }
  };

  let body: ReactNode;
  if (!token || error?.code === "link_invalid") {
    body = <Notice kind="warn">This link is not valid. Sign in and open Your account → Email preferences instead.</Notice>;
  } else if (error?.code === "link_expired") {
    body = (
      <Notice kind="warn">
        This link has expired. <a href="/account#email">Sign in</a> and open Your account → Email preferences, or use the Unsubscribe link in a more
        recent email.
      </Notice>
    );
  } else if (!prefs) {
    body = error ? <ErrorBox error={error} title="Could not load your preferences" /> : <Loading label="Loading…" />;
  } else if (prefs.kind === "unsubscribe" && prefs.category) {
    const cat = prefs.categories[0];
    body = (
      <>
        <ErrorBox error={error} title="Could not do that" />
        {cat && !cat.subscribed ? (
          <Notice kind="success">
            Done: {prefs.email} gets no more {LABEL[prefs.category]} emails from Stackurity. Emails about your account and your organisation still
            arrive.
          </Notice>
        ) : (
          <>
            <p>
              Stop {LABEL[prefs.category]} emails to <strong className="break">{prefs.email}</strong>? Emails about your account and your organisation
              are not affected.
            </p>
            <div className="form-actions">
              <button
                type="button"
                className="btn btn-primary"
                disabled={pending}
                onClick={() => change({ [prefs.category as EmailCategory]: false })}
              >
                Unsubscribe from {LABEL[prefs.category]}
              </button>
            </div>
          </>
        )}
        <p className="small muted">
          To change anything else, use the Email preferences link in the email, or <a href="/account#email">sign in</a>.
        </p>
      </>
    );
  } else {
    body = (
      <>
        <p>
          Emails from Stackurity to <strong className="break">{prefs.email}</strong>:
        </p>
        <ErrorBox error={error} title="Could not save" />
        <CategoryToggles prefs={prefs} onChange={change} pending={pending} />
        {saved && <Notice kind="success">Saved. It applies at once.</Notice>}
        <LockedCategories prefs={prefs} />
      </>
    );
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">Email preferences</h1>
        {body}
      </div>
    </div>
  );
}
