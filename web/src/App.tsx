import { lazy, Suspense, type ReactNode } from "react";
import { Route, Routes } from "react-router";
import type { UserRole } from "./api";
import { useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { ErrorBox, Loading } from "./components/ui";
import { LoginPage, SetupPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { AssetsPage } from "./pages/Assets";
import { AssetDetailPage } from "./pages/AssetDetail";
import { AddServerPage } from "./pages/AddServer";
import { ComponentsPage } from "./pages/Components";
import { ComponentDetailPage } from "./pages/ComponentDetail";
import { CoveragePage } from "./pages/Coverage";
import { IntegrationsPage } from "./pages/Integrations";
import { AuditPage } from "./pages/Audit";
import { ReportsPage } from "./pages/Reports";
import { OutcomesPage } from "./pages/Outcomes";
import { UsersPage } from "./pages/settings/Users";
import { SecretsPage } from "./pages/settings/Secrets";
import { WorkspacesPage } from "./pages/admin/Workspaces";
import { PacksPage } from "./pages/admin/Packs";
import { LicensePage } from "./pages/admin/License";
import { HealthPage } from "./pages/admin/Health";
import { UpdatesPage } from "./pages/admin/Updates";
import { TeamsPage } from "./pages/settings/Teams";
import { TokensPage } from "./pages/settings/Tokens";
import { ConflictsPage } from "./pages/settings/Conflicts";
import { JobsPage } from "./pages/settings/Jobs";
import { NotFound } from "./pages/NotFound";
import { SearchPage } from "./pages/Search";
import { FindingsPage } from "./pages/Findings";
import { FindingDetailPage } from "./pages/FindingDetail";
import { IntelligencePage } from "./pages/Intelligence";
import { IncidentsPage } from "./pages/Incidents";
import { IncidentDetailPage } from "./pages/IncidentDetail";
import { RemediationPage } from "./pages/Remediation";
import { PlanDetailPage } from "./pages/PlanDetail";
import { PluginsPage } from "./pages/settings/Plugins";
import { ActionPlanPage, FixGroupDetailPage } from "./pages/ActionPlan";
import { NotificationsPage } from "./pages/settings/Notifications";
import { RiskPolicyPage } from "./pages/settings/RiskPolicy";

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

export function App() {
  const { state, refresh } = useAuth();

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
        <Route index element={<OverviewPage />} />
        <Route path="search" element={<SearchPage />} />
        <Route path="help" element={help} />
        <Route path="help/:topic" element={help} />
        <Route path="action-plan" element={<ActionPlanPage />} />
        <Route path="action-plan/:id" element={<FixGroupDetailPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="incidents/:id" element={<IncidentDetailPage />} />
        <Route path="remediation" element={<RemediationPage />} />
        <Route path="remediation/plans/:id" element={<PlanDetailPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="findings/:id" element={<FindingDetailPage />} />
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
        <Route path="settings/tokens" element={<TokensPage />} />
        <Route path="settings/risk-policy" element={<RiskPolicyPage />} />
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
          element={
            <RequireRole min="security">
              <NotificationsPage />
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
