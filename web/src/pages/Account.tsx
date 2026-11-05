import { useEffect } from "react";
import { Link, useLocation } from "react-router";
import { useAuth } from "../auth";
import { Card, KeyValues, PageHeader } from "../components/ui";
import { MyEmailPreferences } from "./EmailPreferences";
import { LinkedSlackAccounts } from "./SlackLink";
import { TwoFactorCard } from "./TwoFactor";
import { PasswordCard } from "./Password";
import { ActiveSessionsCard } from "./Sessions";
import { SocialConnectionsCard } from "./Social";

/**
 * /account: the signed-in person, their organisations, and what acts as
 * them elsewhere (linked Slack accounts, AI assistants).
 */
export function AccountPage() {
  const { me, meta } = useAuth();
  const { hash } = useLocation();

  // Links to #slack, #mfa, #sessions, #sign-in or #email land on that section once it is on screen.
  useEffect(() => {
    if (!hash) return;
    const t = setTimeout(() => document.getElementById(hash.slice(1))?.scrollIntoView({ block: "start" }), 50);
    return () => clearTimeout(t);
  }, [hash]);

  const u = me?.user;
  const orgs = me?.workspaces ?? [];
  return (
    <>
      <PageHeader title="Your account" sub="Who you are signed in as, how you sign in, and which other tools can act as you." />
      <Card title="Profile" description="Your name and email address, and the organisations you belong to with your role in each.">
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

      <h2 className="section-title">Signing in</h2>
      <PasswordCard />
      <TwoFactorCard />
      {meta?.social && <SocialConnectionsCard />}
      <ActiveSessionsCard />

      {meta?.email_preferences && (
        <>
          <h2 className="section-title">Emails</h2>
          <MyEmailPreferences />
        </>
      )}

      <h2 className="section-title">Other tools that act as you</h2>
      <Card
        id="slack"
        title="Linked Slack accounts"
        description={
          <>
            Slack accounts whose clicks on Assign to me and Snooze in Stackurity messages act as you in {me?.workspace?.name ?? "this organisation"}, with your
            role and projects.
          </>
        }
      >
        <LinkedSlackAccounts />
      </Card>
      <Card
        title="AI assistants"
        description="Assistants such as Claude or ChatGPT that you allowed to read Stackurity, and act in it, as you. Disconnect any you no longer use."
      >
        <p>
          <Link to="/integrations/ai-assistants#connected">Assistants you allowed to use Stackurity as you</Link>
        </p>
      </Card>
    </>
  );
}
