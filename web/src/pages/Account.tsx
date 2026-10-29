import { useEffect } from "react";
import { Link, useLocation } from "react-router";
import { useAuth } from "../auth";
import { Card, KeyValues, PageHeader } from "../components/ui";
import { LinkedSlackAccounts } from "./SlackLink";
import { TwoFactorCard } from "./TwoFactor";
import { PasswordCard } from "./Password";

/**
 * /account: the signed-in person, their organisations, and what acts as
 * them elsewhere (linked Slack accounts, AI assistants).
 */
export function AccountPage() {
  const { me } = useAuth();
  const { hash } = useLocation();

  // Links to #slack and #mfa land on that section once it is on screen.
  useEffect(() => {
    if (!hash) return;
    const t = setTimeout(() => document.getElementById(hash.slice(1))?.scrollIntoView({ block: "start" }), 50);
    return () => clearTimeout(t);
  }, [hash]);

  const u = me?.user;
  const orgs = me?.workspaces ?? [];
  return (
    <>
      <PageHeader title="Your account" sub="Who you are signed in as, and what acts as you from other tools." />
      <Card title="Profile">
        <KeyValues
          entries={[
            ["Name", u?.name || <span className="muted">not set</span>],
            ["Email", <span className="break">{u?.email ?? ""}</span>],
            [
              "Organisations",
              orgs.length === 0 ? (
                me?.workspace?.name ?? ""
              ) : (
                <ul className="plain-list">
                  {orgs.map((o) => (
                    <li key={o.workspace_id}>
                      {o.name} <span className="muted small">({o.role || "some projects"})</span>
                      {o.workspace_id === me?.workspace?.id && <span className="muted small"> · current</span>}
                    </li>
                  ))}
                </ul>
              ),
            ],
          ]}
        />
      </Card>
      <PasswordCard />
      <TwoFactorCard />
      <section id="slack" className="card">
        <header className="card-head">
          <h2>Linked Slack accounts</h2>
        </header>
        <p className="hint">
          Slack accounts whose clicks on Assign to me and Snooze in Stackurity messages act as you in {me?.workspace?.name ?? "this organisation"}, with your
          role and projects.
        </p>
        <LinkedSlackAccounts />
      </section>
      <Card title="AI assistants">
        <p>
          <Link to="/settings/ai-assistants#connected">Assistants you allowed to use Stackurity as you</Link>
        </p>
      </Card>
    </>
  );
}
