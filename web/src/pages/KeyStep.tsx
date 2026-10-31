import { useState, type FormEvent } from "react";
import { api, type LicenseInfo, type LicenseKeyStatus } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { ErrorBox, Notice } from "../components/ui";

/**
 * A self-hosted server without its key: an instance administrator enters
 * the free key here (or a paid licence); everyone else is told to ask one.
 * Agents and scans keep sending data meanwhile.
 */
export function KeyStepPage({ status }: { status: LicenseKeyStatus }) {
  const { me, refresh, logout } = useAuth();
  const admin = Boolean(me?.user?.instance_admin);
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={140} height={140} />
        </div>
        <h1 className="auth-title">Enter this server&apos;s free key</h1>
        <p>
          {status.upgraded
            ? "This version of Stackurity needs a key, and the 30 days to add one have passed."
            : "Stackurity Community is free to self-host. Each server needs a free key, which you get by signing up with your email."}{" "}
          Nothing has been lost: agents and scans keep sending data, and everything is here once the key is in.
        </p>
        {admin ? <KeyForm status={status} onDone={() => void refresh()} /> : <Notice kind="info">Ask an instance administrator of this server to enter its key.</Notice>}
        <p className="small" style={{ textAlign: "center" }}>
          <button type="button" className="btn btn-link" onClick={() => void logout()}>
            Sign out
          </button>
        </p>
      </div>
    </div>
  );
}

/** Get a key, paste it in. Shared by the key step and the Licence page. */
export function KeyForm({ status, onDone }: { status: LicenseKeyStatus; onDone: () => void }) {
  const info = useLoad(() => api.get<LicenseInfo>("/admin/license"), []);
  const act = useAction();
  const [key, setKey] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (await act.run(() => api.put<LicenseInfo>("/admin/license", { key: key.trim() }))) {
      setKey("");
      onDone();
    }
  };
  if (info.data?.managed_by_env) {
    return (
      <Notice kind="warn">
        This server reads its key from STACKURITY_LICENSE or STACKURITY_LICENSE_FILE, and the key there is missing or not valid. Put a valid key
        there and restart the server. Get a free one at{" "}
        <a href={status.signup_url} target="_blank" rel="noopener noreferrer">
          {status.signup_url}
        </a>
        .
      </Notice>
    );
  }
  return (
    <form className="form" onSubmit={submit}>
      <ol className="steps small">
        <li>
          <a href={status.signup_url} target="_blank" rel="noopener noreferrer">
            Get a free key
          </a>{" "}
          (from any computer; it is emailed to you).
        </li>
        <li>Paste it below.</li>
      </ol>
      <ErrorBox error={act.error} title="That key did not work" />
      <div className="field">
        <label htmlFor="key-step">Key</label>
        <textarea id="key-step" rows={4} required value={key} onChange={(e) => setKey(e.target.value)} spellCheck={false} />
        <p className="hint">Checked on this server, offline; nothing is sent anywhere. A paid licence key works here too.</p>
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending || key.trim() === ""}>
          Enter key
        </button>
      </div>
    </form>
  );
}
