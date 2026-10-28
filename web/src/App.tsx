import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation, useParams } from "react-router";
import type { UserRole } from "./api";
import { useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { ErrorBox, Loading } from "./components/ui";
import { LoginPage, SetupPage } from "./pages/Login";
import { AcceptInvitePage } from "./pages/AcceptInvite";
import { SlackLinkPage } from "./pages/SlackLink";
import { AccountPage } from "./pages/Account";
import { SlackOAuthCallbackPage } from "./pages/SlackOAuthCallback";
import { SlackInstallPage } from "./pages/SlackInstall";
import { EmailConfirmPage, EmailStopPage } from "./pages/EmailConfirm";
import { AssistantsPage, ConnectAssistantPage } from "./pages/Assistants";
import { OnboardingPage } from "./pages/Onboarding";
import { SignupPage, VerifySignupPage } from "./pages/Signup";
import { UsagePage } from "./pages/settings/Usage";
import { BillingPage } from "./pages/settings/Billing";
import { HomePage } from "./pages/Home";
import { AutomaticFixPoliciesPage, SettingsPage } from "./pages/Settings";
import { AssetsPage } from "./pages/Assets";
import { AssetDetailPage } from "./pages/AssetDetail";
import { AddServerPage } from "./pages/AddServer";
import { ComponentsPage } from "./pages/Components";
import { ComponentDetailPage } from "./pages/ComponentDetail";
import { CoveragePage } from "./pages/Coverage";
import { IntegrationsPage } from "./pages/Integrations";
import { AuditPage } from "./pages/Audit";
import { ApprovalsPage } from "./pages/Approvals";
import { ChecksPage } from "./pages/Checks";
import { ReportsPage } from "./pages/Reports";
import { OutcomesPage } from "./pages/Outcomes";
import { UsersPage } from "./pages/settings/Users";
import { SecretsPage } from "./pages/settings/Secrets";
import { WorkspacesPage } from "./pages/admin/Workspaces";
import { PacksPage } from "./pages/admin/Packs";
import { LicensePage } from "./pages/admin/License";
import { HealthPage } from "./pages/admin/Health";
import { CoverageGapsPage } from "./pages/admin/CoverageGaps";
import { UpdatesPage } from "./pages/admin/Updates";
import { TeamsPage } from "./pages/settings/Teams";
import { TokensPage } from "./pages/settings/Tokens";
import { ConflictsPage } from "./pages/settings/Conflicts";
import { JobsPage } from "./pages/settings/Jobs";
import { NotFound } from "./pages/NotFound";
import { SearchPage } from "./pages/Search";
import { IssuesPage } from "./pages/Findings";
import { FindingDetailPage } from "./pages/FindingDetail";
import { IntelligencePage } from "./pages/Intelligence";
import { IncidentsPage } from "./pages/Incidents";
import { IncidentDetailPage } from "./pages/IncidentDetail";
import { AutomaticFixesPage } from "./pages/Remediation";
import { PlanDetailPage } from "./pages/PlanDetail";
import { PluginsPage } from "./pages/settings/Plugins";
import { FixesPage, FixGroupDetailPage } from "./pages/ActionPlan";
import { IntegrationsHubPage } from "./pages/settings/Integrations";
import { IntegrationAddPage, IntegrationChannelPage } from "./pages/settings/IntegrationsChannel";
import { RiskPolicyPage } from "./pages/settings/RiskPolicy";
import { FixGroupingPage } from "./pages/settings/FixGrouping";
import { ProjectDetailPage, ProjectsPage } from "./pages/settings/Projects";

// The help articles are large and rarely needed, so they load on demand.
const HelpPage = lazy(() => import("./pages/Help").then((m) => ({ default: m.HelpPage })));
const help = (
  <Suspense fallback={<Loading />}>
    <HelpPage />
  </Suspense>
);

function RequireRole({ min, children }: { min: UserRole; children: ReactNode }) {
  const { can } = useAuth();
  if (!can(min)) {
    return (
      <div className="alert alert-warn" role="alert">
        This page needs the <strong>{min}</strong> role or higher. Ask an administrator if you need access.
      </div>
    );
  }
  return <>{children}</>;
}

/**
 * Sends an old address to its new page, keeping the query and hash, so
 * bookmarks and links in Slack, email and Jira keep working.
 */
function Moved({ to }: { to: (params: Record<string, string | undefined>, search: URLSearchParams) => string }) {
  const params = useParams();
  const { search, hash } = useLocation();
  const target = to(params, new URLSearchParams(search));
  const keep = target.includes("?") ? "" : search;
  return <Navigate replace to={target + keep + hash} />;
}

function RequireInstanceAdmin({ children }: { children: ReactNode }) {
  const { me } = useAuth();
  if (!me?.user?.instance_admin) {
    return (
      <div className="alert alert-warn" role="alert">
        This page is for instance administrators, who operate this installation.
      </div>
    );
  }
  return <>{children}</>;
}

/** Back from Slack with a code and our state: the exchange needs the signed-in person. */
function slackCallbackNeedsSession(): boolean {
  const q = new URLSearchParams(window.location.search);
  return Boolean(q.get("code") && q.get("state") && !q.get("error"));
}

export function App() {
  const { state, refresh } = useAuth();
  const { pathname } = useLocation();

  // An invitation link works signed in or not, before any other page.
  if (pathname === "/invite" && (state.phase === "login" || state.phase === "ready")) return <AcceptInvitePage />;
  // Sign-up, where the server offers it (a hosted edition).
  const signup = "meta" in state ? state.meta.signup : undefined;
  if (signup && pathname === "/signup/verify" && (state.phase === "login" || state.phase === "ready")) return <VerifySignupPage />;
  if (signup && pathname === "/signup" && state.phase === "login") return <SignupPage signup={signup} />;
  // A link from Slack to connect a Slack account: sign in first, then
  // confirm. The address (and its #token) stays the same while signing in.
  if (pathname === "/slack/link" && state.phase === "login") return <LoginPage />;
  if (pathname === "/slack/link" && state.phase === "ready") return <SlackLinkPage />;
  // An AI assistant asking to connect (OAuth): sign in first, then allow.
  // The address and its query stay the same while signing in.
  if (pathname === "/oauth/authorize" && state.phase === "login") return <LoginPage />;
  if (pathname === "/oauth/authorize" && state.phase === "ready") return <ConnectAssistantPage />;
  // Back from "Add to Slack": sign in first; the address and query stay.
  // Without our state (an install Slack started) or with an error (Cancel
  // on Slack's page) there is nothing to exchange: the page explains, signed
  // in or not.
  if (pathname === "/integrations/slack/oauth/callback" && state.phase === "login") return slackCallbackNeedsSession() ? <LoginPage /> : <SlackOAuthCallbackPage />;
  if (pathname === "/integrations/slack/oauth/callback" && state.phase === "ready") return <SlackOAuthCallbackPage />;
  // Adding Stackurity to Slack from outside the dashboard (the Slack app's
  // Direct install URL): sign in, pick the organisation, go to Slack.
  if ((pathname === "/integrations/slack/install" || pathname === "/integrations/slack/add") && state.phase === "login") return <LoginPage />;
  if ((pathname === "/integrations/slack/install" || pathname === "/integrations/slack/add") && state.phase === "ready") return <SlackInstallPage />;
  // Confirming an email address for notifications works signed in or not.
  if (pathname === "/email/confirm" && (state.phase === "login" || state.phase === "ready")) return <EmailConfirmPage />;
  // Stopping email sent by Stackurity, signed in or not.
  if (pathname === "/email/unsubscribe" && (state.phase === "login" || state.phase === "ready")) return <EmailStopPage kind="unsubscribe" />;
  if (pathname === "/email/block" && (state.phase === "login" || state.phase === "ready")) return <EmailStopPage kind="block" />;

  switch (state.phase) {
    case "loading":
      return (
        <div className="center-screen">
          <Loading />
        </div>
      );
    case "error":
      return (
        <div className="center-screen">
          <div className="auth-card">
            <h1>Stackurity</h1>
            <ErrorBox error={state.error} title="Cannot load" />
            <button type="button" className="btn" onClick={() => void refresh()}>
              Retry
            </button>
          </div>
        </div>
      );
    case "setup":
      return <SetupPage />;
    case "login":
      return <LoginPage />;
  }

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<HomePage />} />
        <Route path="search" element={<SearchPage />} />
        <Route path="get-started" element={<OnboardingPage />} />
        <Route path="help" element={help} />
        <Route path="help/:topic" element={help} />
        <Route path="fixes" element={<FixesPage />} />
        <Route path="fixes/issues" element={<IssuesPage />} />
        <Route path="fixes/automatic" element={<AutomaticFixesPage />} />
        <Route path="fixes/:id" element={<FixGroupDetailPage />} />
        <Route path="action-plan" element={<Moved to={() => "/fixes"} />} />
        <Route path="action-plan/:id" element={<Moved to={(p) => `/fixes/${encodeURIComponent(p.id ?? "")}`} />} />
        <Route path="findings" element={<Moved to={() => "/fixes/issues"} />} />
        <Route path="findings/:id" element={<FindingDetailPage />} />
        <Route
          path="remediation"
          element={
            <Moved
              to={(_p, q) => {
                if (q.get("tab") === "policies") return "/settings/automatic-fixes";
                q.delete("tab");
                const rest = q.toString();
                return `/fixes/automatic${rest ? `?${rest}` : ""}`;
              }}
            />
          }
        />
        <Route path="remediation/plans/:id" element={<PlanDetailPage />} />
        <Route path="activity" element={<Moved to={() => "/incidents"} />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="incidents/:id" element={<IncidentDetailPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route
          path="settings/automatic-fixes"
          element={
            <RequireRole min="security">
              <AutomaticFixPoliciesPage />
            </RequireRole>
          }
        />
        <Route path="intelligence" element={<IntelligencePage />} />
        <Route path="assets" element={<AssetsPage />} />
        <Route
          path="assets/add"
          element={
            <RequireRole min="admin">
              <AddServerPage />
            </RequireRole>
          }
        />
        <Route path="assets/:id" element={<AssetDetailPage />} />
        <Route path="components" element={<ComponentsPage />} />
        <Route path="components/:id" element={<ComponentDetailPage />} />
        <Route path="coverage" element={<CoveragePage />} />
        <Route
          path="integrations"
          element={
            <RequireRole min="engineer">
              <IntegrationsPage />
            </RequireRole>
          }
        />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="outcomes" element={<OutcomesPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="checks" element={<ChecksPage />} />
        <Route path="approvals" element={<ApprovalsPage />} />
        <Route path="settings/approvals" element={<Moved to={() => "/approvals"} />} />
        <Route path="settings/tokens" element={<TokensPage />} />
        <Route
          path="settings/usage"
          element={
            <RequireRole min="admin">
              <UsagePage />
            </RequireRole>
          }
        />
        <Route
          path="settings/billing"
          element={
            <RequireRole min="admin">
              <BillingPage />
            </RequireRole>
          }
        />
        <Route path="account" element={<AccountPage />} />
        {/* Linked Slack accounts moved to Your account. */}
        <Route path="settings/slack" element={<Navigate replace to="/account#slack" />} />
        <Route path="settings/ai-assistants" element={<AssistantsPage />} />
        <Route path="settings/assistants" element={<Navigate replace to="/settings/ai-assistants#connected" />} />
        <Route path="settings/risk-policy" element={<RiskPolicyPage />} />
        <Route path="settings/fix-grouping" element={<FixGroupingPage />} />
        <Route
          path="settings/plugins"
          element={
            <RequireRole min="admin">
              <PluginsPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/notifications"
          element={<Moved to={(_p, q) => (q.get("tab") === "deliveries" ? "/settings/integrations?tab=deliveries" : "/settings/integrations")} />}
        />
        <Route
          path="settings/integrations"
          element={
            <RequireRole min="engineer">
              <IntegrationsHubPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/integrations/channels/:id"
          element={
            <RequireRole min="security">
              <IntegrationChannelPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/integrations/new/:kind"
          element={
            <RequireRole min="admin">
              <IntegrationAddPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/users"
          element={
            <RequireRole min="admin">
              <UsersPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/projects"
          element={
            <RequireRole min="admin">
              <ProjectsPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/projects/:id"
          element={
            <RequireRole min="admin">
              <ProjectDetailPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/teams"
          element={
            <RequireRole min="admin">
              <TeamsPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/conflicts"
          element={
            <RequireRole min="admin">
              <ConflictsPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/jobs"
          element={
            <RequireRole min="admin">
              <JobsPage />
            </RequireRole>
          }
        />
        <Route
          path="settings/secrets"
          element={
            <RequireRole min="admin">
              <SecretsPage />
            </RequireRole>
          }
        />
        <Route
          path="admin/workspaces"
          element={
            <RequireInstanceAdmin>
              <WorkspacesPage />
            </RequireInstanceAdmin>
          }
        />
        <Route
          path="admin/license"
          element={
            <RequireInstanceAdmin>
              <LicensePage />
            </RequireInstanceAdmin>
          }
        />
        <Route
          path="admin/health"
          element={
            <RequireInstanceAdmin>
              <HealthPage />
            </RequireInstanceAdmin>
          }
        />
        <Route
          path="admin/coverage-gaps"
          element={
            <RequireInstanceAdmin>
              <CoverageGapsPage />
            </RequireInstanceAdmin>
          }
        />
        <Route
          path="admin/packs"
          element={
            <RequireInstanceAdmin>
              <PacksPage />
            </RequireInstanceAdmin>
          }
        />
        <Route
          path="updates"
          element={
            <RequireInstanceAdmin>
              <UpdatesPage />
            </RequireInstanceAdmin>
          }
        />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
