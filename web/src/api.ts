// Typed client for the Stackurity REST API (/api/v1). Types mirror the Go
// structs in internal/store/*.go and the handlers in internal/api/.

export type Role = "viewer" | "engineer" | "security" | "admin" | "collector";
export type UserRole = Exclude<Role, "collector">;

export const USER_ROLES: UserRole[] = ["viewer", "engineer", "security", "admin"];
const RANK: Record<string, number> = { viewer: 1, engineer: 2, security: 3, admin: 4 };

/** Mirrors auth.Role.AtLeast: collector tokens rank below every user role. */
export function atLeast(role: Role | undefined, min: UserRole): boolean {
  if (!role) return false;
  return (RANK[role] ?? 0) >= RANK[min];
}

export const ASSET_KINDS = ["host", "repository", "image", "application", "managed_service", "sbom", "cluster", "workload"] as const;
export const ASSET_STATUSES = ["ok", "partial", "stale"] as const;
export const CRITICALITIES = ["unknown", "low", "medium", "high", "critical"] as const;
export const RELATION_KINDS = ["runs_on", "built_from", "deployed_as", "contains", "depends_on", "replica_of"] as const;
export const COVERAGE_STATUSES = ["checked", "partial", "skipped", "failed", "unsupported"] as const;

export interface List<T> {
  items: T[];
  total: number;
  limit?: number;
  offset?: number;
}

export interface Meta {
  name: string;
  version: string;
  api: string;
  setup_required: boolean;
  /** Present when single sign-on is configured. */
  sso?: { label: string; login_url: string };
}

export interface User {
  id: number;
  email: string;
  name: string;
  role: UserRole;
  disabled: boolean;
  created_at: string;
  last_login_at: string | null;
  teams: string[] | null;
  /** Operates the installation: manages workspaces. */
  instance_admin: boolean;
}

/** One workspace the signed-in user belongs to, with their role there. */
export interface Membership {
  workspace_id: number;
  name: string;
  slug: string;
  role: UserRole;
}

export interface Workspace {
  id: number;
  name: string;
  slug: string;
  created_at: string;
  disabled_at: string | null;
  member_count: number;
  asset_count: number;
  plan: "inherit" | Edition;
}

export interface PackManifest {
  id: string;
  version: string;
  name: string;
  publisher: string;
  license: string;
  description: string;
  files: string[];
  purl_types: string[];
  known_limitations?: string[];
}

export interface InstalledPack {
  id: string;
  version: string;
  name: string;
  publisher: string;
  trust: "official" | "verified" | "unsigned";
  sha256: string;
  enabled: boolean;
  files: string[];
  purl_types: string[];
}

/** An official pack that would read files reported as unsupported. */
export interface PackSuggestion {
  id: string;
  name: string;
  description: string;
  files: number;
}

export interface PackList {
  installed: InstalledPack[];
  suggestions: PackSuggestion[];
}

export interface AdminPacks extends PackList {
  catalog: { manifest: PackManifest; sha256: string; installed_version: string }[];
}

/** A stored secret; its value is never returned. */
export interface SecretInfo {
  name: string;
  created_at: string;
  updated_at: string;
}

export interface Token {
  id: number;
  name: string;
  prefix: string;
  user_id: number | null;
  role: Role;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  user_email?: string;
}

export interface Me {
  user: User | null;
  role: Role;
  token: Token | null;
  /** The workspace this session or token works in; null when the user belongs to none. */
  workspace: { id: number; name: string; slug: string } | null;
  /** Workspaces the signed-in user can switch to (sessions only). */
  workspaces: Membership[];
  /** Edition in effect for this workspace, and the paid features it includes. */
  edition: Edition;
  features: Feature[];
  /** Whether Send feedback is on (STACKURITY_FEEDBACK_URL) for this signed-in user. */
  feedback_enabled?: boolean;
}

export type Edition = "community" | "pro" | "enterprise";
export type Feature = "remediation" | "teams" | "evidence_report" | "sso" | "enterprise_packs";

export interface LicenseInfo {
  status: {
    state: "none" | "active" | "grace" | "expired";
    edition: Edition;
    grace_ends?: string;
    features: Feature[];
    license?: { id: string; customer: string; email?: string; edition: Edition; max_assets: number; issued_at: string; expires_at: string };
  };
  active_assets: number;
  managed_by_env: boolean;
}

/** GET /admin/health: whether the installation itself is working. */
/** What a platform problem affects. Items are named only in the viewer's active workspace. */
export interface HealthScope {
  summary: string;
  count?: number;
  workspaces?: number;
  items?: { name: string; detail?: string; last_success?: string | null; last_error?: string; link?: string }[];
  /** Affected objects not listed: in other workspaces, or beyond the first ten. */
  hidden?: number;
}

export interface HealthProblem {
  severity: "critical" | "warning";
  kind: "feed" | "task" | "jobs" | "intelligence" | "platform" | "integration" | "notification" | "notifications" | "collector" | "coverage" | "schema" | "config";
  key: string;
  title: string;
  detail?: string;
  /** When it last worked; null when it never did or it does not apply. */
  last_success?: string | null;
  last_error?: string;
  scope?: HealthScope;
  next_step?: string;
  /** Documentation section, a repository path such as docs/install.md#health. */
  docs?: string;
}

export interface PlatformHealth {
  status: "ok" | "warning" | "critical";
  checked_at: string;
  problems: HealthProblem[];
  tasks: {
    name: string;
    every_seconds: number;
    last_started_at: string | null;
    last_success_at: string | null;
    last_error: string;
    consecutive_failures: number;
    running: boolean;
  }[];
  jobs: { kind: string; state: "queued" | "scheduled" | "running" | "failed"; count: number }[];
  oldest_queued_seconds: number;
  recent_failures: { id: number; kind: string; workspace_id: number | null; attempts: number; last_error: string; failed_at: string }[];
  /** Notification deliveries by channel kind and state; failed means in the last 24 hours. */
  deliveries: { kind: string; state: "pending" | "retrying" | "held" | "failed"; count: number }[];
  oldest_due_delivery_seconds: number;
  failing_channels: { kind: string; count: number }[];
}

/** One published, stable release newer than the running one. */
export interface UpdateRelease {
  version: string;
  tag: string;
  name: string;
  url: string;
  published_at: string;
  /** Release notes, Markdown (cut at about 16 KB). */
  notes: string;
  notes_truncated?: boolean;
  /** The notes have a "Security" section. */
  security: boolean;
}

/** GET /updates (instance admins): is a newer release available? */
export interface UpdateStatus {
  /** False when the operator set STACKURITY_UPDATE_CHECK=off. */
  enabled: boolean;
  current: string;
  /** False for development builds, which never show an update. */
  comparable: boolean;
  latest: string;
  latest_url?: string;
  latest_published_at?: string;
  update_available: boolean;
  security: boolean;
  checked_at?: string;
  releases: UpdateRelease[];
}

export interface Asset {
  id: number;
  kind: string;
  name: string;
  environment: string;
  owner_team_id: number | null;
  owner_team: string;
  provider: string;
  region: string;
  criticality: string;
  internet_exposed: boolean | null;
  /** Exposure risk scoring uses: internet_exposed when set by hand, else what a
   * collector observed (a Kubernetes workload, or the workloads running an image). */
  exposed: boolean | null;
  tags: string[];
  attributes: Record<string, string> | null;
  first_seen: string;
  last_seen: string;
  collection_status: string;
  component_count: number;
}

export interface Identifier {
  scheme: string;
  value: string;
  first_seen?: string;
}

export interface AssetDetail {
  asset: Asset;
  identifiers: Identifier[] | null;
}

export interface AssetUpdate {
  name?: string;
  environment?: string;
  owner_team_id?: number | null; // null or 0 clears
  criticality?: string;
  internet_exposed?: boolean | null; // null resets to unknown
  tags?: string[];
  provider?: string;
  region?: string;
}

export interface InventoryRow {
  id: number;
  asset_id: number;
  asset_name: string;
  asset_kind: string;
  component_id: number;
  type: string;
  namespace: string;
  name: string;
  purl: string;
  version: string;
  location: string;
  collector_id: string;
  direct: boolean | null;
  scope: string;
  confidence: string;
  evidence: Record<string, string> | null;
  first_seen: string;
  last_seen: string;
  collection_id: number;
  removed_at: string | null;
  latest_stable?: string;
  update_type?: "patch" | "minor" | "major" | "";
  open_findings?: number;
  /** Whether vulnerability intelligence covered this row (docs/compatibility.md, "Coverage states"). */
  coverage?: RowCoverage;
  coverage_reason?: string;
  coverage_feed?: string;
  evaluated_at?: string | null;
  /** Upstream end of life on a distribution package (docs/compatibility.md, "Lifecycle of distribution packages"). */
  lifecycle_note?: LifecycleNote | null;
}

export interface LifecycleNote {
  /** distribution_supported (no finding), distribution_ended or third_party_build. */
  status?: "distribution_supported" | "distribution_ended" | "third_party_build";
  text?: string;
  product?: string;
  cycle?: string;
  subject?: string;
  upstream_eol?: string;
  distribution?: string;
  distribution_eol?: string;
}

export type RowCoverage = "evaluated" | "stale_intelligence" | "not_evaluated" | "unsupported" | "awaiting";

/** How far an asset's findings can be trusted (GET /assets/{id}/coverage-summary). */
export interface CoverageSummary {
  asset_id: number;
  state: string;
  label: string;
  states: { state: string; label: string; detail: string }[];
  components: {
    total: number;
    evaluated: number;
    stale_intelligence: number;
    not_evaluated: number;
    unsupported: number;
    awaiting: number;
  };
  collection: {
    status: string;
    last_seen: string;
    last_collection: string | null;
    failed_scopes: number;
    partial_scopes: number;
    unsupported_scopes: number;
  };
  last_evaluated: string | null;
  gap_reasons: { reason: string; coverage: string; components: number }[];
  stale_feeds: string[];
}

export interface CoverageRow {
  asset_id: number;
  asset_name: string;
  collector_id: string;
  scope: string;
  status: string;
  reason: string;
  tool_version: string;
  last_attempt: string;
  last_success: string | null;
}

export interface Collection {
  id: number;
  asset_id: number;
  collector_id: string;
  collector_version: string;
  method: string;
  observed_at: string;
  received_at: string;
  complete: boolean;
  observation_count: number;
}

export interface Relation {
  from_asset: number;
  from_name: string;
  to_asset: number;
  to_name: string;
  kind: string;
  source: string;
  created_at: string;
}

export const DRIFT_STATUSES = ["behind", "only_there", "differs", "ahead", "only_here"] as const;
export type DriftStatus = (typeof DRIFT_STATUSES)[number];

export interface DriftItem {
  component_id: number;
  name: string;
  type: string;
  /** Versions on the asset itself. */
  versions: string[] | null;
  /** Versions on the compared (reference) asset. */
  reference: string[] | null;
  status: DriftStatus | string;
}

export interface Drift {
  asset_id: number;
  reference_id: number;
  items: DriftItem[] | null;
  counts: Record<string, number> | null;
  truncated: boolean;
}

export interface DriftResponse {
  drift: Drift;
  reference: Asset;
}

// --- Stage 7: an asset's stack (GET /assets/{id}/stack)

export const STACK_ROLES = ["self", "host", "cluster", "source", "image", "dependency", "workload", "deployment"] as const;
export type StackRole = (typeof STACK_ROLES)[number];

/** Layers in the order the API returns them: most exposed first. */
export const STACK_LAYERS = ["web_server", "os", "runtime", "data_store", "libraries", "declared", "managed_service", "platform", "other"] as const;
export type StackLayerName = (typeof STACK_LAYERS)[number];

export interface StackMember {
  asset_id: number;
  name: string;
  kind: string;
  environment: string;
  internet_exposed: boolean | null;
  criticality: string;
  collection_status: string;
  role: StackRole | string;
  /** Relation kind that brought this member in ("" for the asset itself). */
  via: string;
  /** The member it was reached from (0 for the asset itself). */
  from: number;
  open: number;
}

export interface StackLayer {
  layer: StackLayerName | string;
  open: number;
  by_severity: Record<string, number> | null;
  known_exploited: number;
  overdue: number;
}

export type StackFinding = Finding & { layer: StackLayerName | string };

export interface Stack {
  root: number;
  members: StackMember[] | null;
  /** Only non-empty layers, most exposed first. */
  layers: StackLayer[] | null;
  findings: StackFinding[] | null;
  /** True when only the first 5,000 findings were returned. */
  truncated: boolean;
}

export interface Component {
  id: number;
  purl_key: string;
  type: string;
  namespace: string;
  name: string;
  asset_count: number;
  versions: string[] | null;
  created_at: string;
}

export interface Overview {
  assets: Record<string, number>;
  asset_status: Record<string, number>;
  components: number;
  inventory_rows: number;
  ecosystems: Record<string, number>;
  coverage_status: Record<string, number>;
  identity_conflicts: number;
  last_collection: string | null;
  confidence: Record<string, number>;
  /** Linux hosts running older code than is installed (reboot pending). */
  reboot_required?: number;
  /** Assets by coverage state (healthy, stale_intelligence, failed_collection, ...). */
  asset_coverage?: Record<string, number>;
  /** Components by row coverage (evaluated, not_evaluated, unsupported, ...). */
  component_coverage?: Record<string, number>;
}

export interface Team {
  id: number;
  name: string;
  email: string;
  created_at: string;
  members: number[] | null;
  asset_count: number;
}

export interface ConflictAsset {
  id: number;
  name: string;
  kind: string;
  last_seen: string;
  component_count: number;
}

export interface Conflict {
  id: number;
  asset_ids: number[];
  identifiers: Identifier[] | null;
  detected_at: string;
  assets?: ConflictAsset[] | null;
}

export interface Facets {
  environments: string[] | null;
  asset_kinds: string[] | null;
  component_types: string[] | null;
}

/** Response of endpoints that enqueue background work. */
export interface Queued {
  job_id: number;
  queued: boolean;
}

export interface AuditEvent {
  id: number;
  at: string;
  actor_type: string;
  actor_id: number | null;
  actor_name: string;
  action: string;
  object_type: string;
  object_id: string;
  detail: unknown;
  remote_addr: string;
}

export interface Job {
  id: number;
  kind: string;
  payload: unknown;
  attempts: number;
  max_attempts: number;
  run_at: string;
  last_error: string;
  done_at: string | null;
  failed_at: string | null;
  created_at: string;
}

export interface GitRepoConfig {
  url: string;
  ref?: string;
  environment?: string;
  username?: string;
}

export interface ContainerImageConfig {
  image: string;
  environment?: string;
  platform?: string;
  username?: string;
}

export interface PluginIntegrationConfig {
  plugin: string;
  config?: Record<string, unknown>;
}

export const INTEGRATION_KINDS = ["git_repository", "container_image", "plugin"] as const;
export type IntegrationKind = (typeof INTEGRATION_KINDS)[number];

/** Union of the per-kind config objects; check `kind` before reading. */
export type IntegrationConfig = Partial<GitRepoConfig> & Partial<ContainerImageConfig> & Partial<PluginIntegrationConfig>;

export interface Integration {
  id: number;
  kind: IntegrationKind | string;
  name: string;
  config: IntegrationConfig;
  secret_ref: string;
  schedule_minutes: number;
  enabled: boolean;
  asset_id: number | null;
  last_attempt: string | null;
  last_success: string | null;
  last_error: string;
  created_at: string;
}

// --- Stage 2: vulnerability, version and lifecycle intelligence

export const SEVERITIES = ["critical", "high", "medium", "low", "none", "unknown"] as const;
export const VERIFICATIONS = ["confirmed", "needs_validation", "stale"] as const;

/** Labels for the evidence states reports count (store.evidenceState). */
export const EVIDENCE_STATE_LABEL: Record<string, string> = {
  confirmed: "confirmed",
  needs_validation: "needs validation (version not confirmed)",
  stale: "stale (asset stopped reporting)",
  stale_intelligence: "confirmed, stale advisory data",
  unknown: "unknown",
  rejected: "rejected",
};

export interface FindingEvidence {
  matched_ranges?: string[];
  osv_ecosystems?: string[];
  osv_package?: string;
  target_ecosystem?: string;
  installed?: string;
  comparator?: string;
  feed?: string;
  feed_last_success?: string;
  feed_stale?: boolean;
  inventory_conf?: string;
  known_exploited?: boolean;
  advisory_level?: string;
  // end_of_life
  product?: string;
  cycle?: string;
  source?: string;
  link?: string;
  eol_date?: string;
  latest_in_cycle?: string;
  // fix grouping hints
  not_running_kernel?: boolean;
  requires_ubuntu_pro?: boolean;
  requires_subscription?: string;
  // kernels: the installed kernel version this finding covers and its packages
  kernel_release?: string;
  kernel_packages?: string[];
  // end_of_life on a distribution package whose finding stands
  distribution?: LifecycleNote;
  [k: string]: unknown;
}

export interface Finding {
  id: number;
  kind: "vulnerability" | "end_of_life" | string;
  key: string;
  inventory_id: number;
  asset_id: number;
  asset_name: string;
  asset_kind: string;
  environment: string;
  component_id: number;
  component_name: string;
  component_type: string;
  version: string;
  location: string;
  direct: boolean | null;
  status: "open" | "resolved" | string;
  verification: string;
  severity: string;
  score: number | null;
  title: string;
  fixed_version: string;
  sources: string[] | null;
  evidence: FindingEvidence | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  resolution: string;
  known_exploited: boolean;
  // Stage 3: workflow and priority
  state?: FindingState;
  priority?: Priority | "";
  priority_score?: number;
  priority_factors?: PriorityFactor[] | null;
  /** Version of the risk policy that produced the priority; empty until next prioritised. */
  priority_policy_version?: string;
  sos?: boolean;
  sos_rule?: string;
  fix_group?: string;
  assignee_user_id?: number | null;
  assignee_email?: string;
  assignee_team_id?: number | null;
  assignee_team?: string;
  ack_due?: string | null;
  fix_due?: string | null;
  acknowledged_at?: string | null;
  suppressed_until?: string | null;
  state_reason?: string;
  /** What reduces the risk while a finding is suppressed or accepted. */
  mitigation?: string;
  escalation_level?: number;
  incident_id?: number | null;
  overdue?: boolean;
}

export interface FindingSummary {
  by_severity: Record<string, number> | null;
  by_kind: Record<string, number> | null;
  by_verification: Record<string, number> | null;
  known_exploited: number;
  fix_available: number;
  affected_assets: number;
  evaluation_gaps: number;
  stale_feeds: number;
  by_priority?: Record<string, number> | null;
  by_state?: Record<string, number> | null;
  sos?: number;
  overdue?: number;
  unassigned?: number;
  /** Findings resolved in the last 7 days. */
  resolved_7d?: number;
}

export interface AdvisoryReference {
  type?: string;
  url?: string;
}

export interface Advisory {
  id: string;
  feed: string;
  group_key: string;
  aliases: string[] | null;
  summary: string;
  severity: string;
  score: number | null;
  vector: string;
  severity_source: string;
  published: string | null;
  modified: string;
  withdrawn: string | null;
  references: AdvisoryReference[] | null;
  known_exploited: boolean;
  fetched_at?: string;
}

// --- global search (GET /search), mirrors internal/store/search.go

/** 0: exact id, name or identifier; 1: prefix; 2: substring. */
export type SearchRank = 0 | 1 | 2;

export interface SearchRef {
  id: number;
  name: string;
  version?: string;
}

export interface SearchVuln {
  key: string;
  /** Empty when the advisory exists but nothing in the workspace is affected. */
  kind: "vulnerability" | "end_of_life" | "";
  rank: SearchRank;
  title: string;
  severity: string;
  score: number | null;
  known_exploited: boolean;
  open_findings: number;
  resolved_findings: number;
  affected_assets: number;
  assets: SearchRef[];
  components: string[];
  advisory?: {
    ids: string[];
    aliases: string[];
    summary: string;
    severity: string;
    score: number | null;
    known_exploited: boolean;
    published: string | null;
    withdrawn: string | null;
  };
}

export interface SearchComponent {
  id: number;
  purl_key: string;
  type: string;
  namespace: string;
  name: string;
  rank: SearchRank;
  asset_count: number;
  versions: string[];
  open_findings: number;
  assets: SearchRef[];
  version?: string;
  version_assets: number;
}

export interface SearchAsset {
  id: number;
  kind: string;
  name: string;
  environment: string;
  owner_team: string;
  collection_status: string;
  last_seen: string;
  rank: SearchRank;
  match_scheme: string;
  match_value: string;
  open_findings: number;
}

export interface SearchTeam {
  id: number;
  name: string;
  email: string;
  rank: SearchRank;
  asset_count: number;
  open_findings: number;
}

/** A finding key whose open findings have a title matching the search. */
export interface SearchFinding {
  key: string;
  kind: "vulnerability" | "end_of_life" | string;
  title: string;
  rank: SearchRank;
  severity: string;
  score: number | null;
  open_findings: number;
  affected_assets: number;
  assets: SearchRef[];
}

/** A member of the current workspace; only returned to engineers and above. */
export interface SearchMember {
  id: number;
  name: string;
  email: string;
  role: Role;
  disabled: boolean;
  rank: SearchRank;
  open_assigned: number;
}

export interface SearchResults {
  query: string;
  vulnerabilities: SearchVuln[];
  findings: SearchFinding[];
  assets: SearchAsset[];
  components: SearchComponent[];
  teams: SearchTeam[];
  members: SearchMember[];
  more: Partial<Record<"vulnerabilities" | "findings" | "assets" | "components" | "teams" | "members", boolean>>;
}

export const SEARCH_MIN_LENGTH = 2;
export const SEARCH_MAX_LENGTH = 200;

export interface FindingDetail {
  finding: Finding;
  advisories?: Advisory[] | null;
  /** Advisories sharing the CVE that did not match this component. */
  related_advisories?: Advisory[] | null;
  /** For open findings: the version to upgrade this installed copy to. */
  upgrade?: UpgradeRecommendation | null;
}

/** Support status of one release line (endoflife.date). */
export interface UpgradeLine {
  product: string;
  cycle: string;
  status: "supported" | "security_only" | "end_of_life" | string;
  support_until?: string | null;
  eol_date?: string | null;
  latest?: string;
  link?: string;
}

/** GET /findings/{id}/upgrade, /components/{id}/upgrade: built only from stored advisory, release and lifecycle data. */
export interface UpgradeRecommendation {
  purl_type: string;
  installed_version: string;
  minimum_fixed_version?: string;
  recommended_version?: string;
  /** distro_fixed, latest_in_line, minimum_fixed, supported_line or none. */
  basis: string;
  change_type?: string;
  requires_major: boolean;
  requires_subscription?: string;
  /** available, none, failed or not_applicable (OS packages). */
  release_data: string;
  release_source?: string;
  release_checked_at?: string | null;
  latest_stable?: string;
  latest_in_line?: string;
  recommended_yanked: boolean;
  minimum_fixed_yanked: boolean;
  yanked_reason?: string;
  installed_yanked: boolean;
  deprecated?: string;
  minimum_fixed_not_in_release_data: boolean;
  lifecycle?: UpgradeLine | null;
  target_lifecycle?: UpgradeLine | null;
  supported_line?: UpgradeLine | null;
  fixes: string[] | null;
  unfixed: string[] | null;
  rationale: string[] | null;
  open_findings: number;
}

export interface VersionUpgrade extends UpgradeRecommendation {
  version: string;
  distro?: string;
  asset_count: number;
}

export interface OutcomeTiming {
  priority: string; // P1..P4 or "all"
  kind: string; // vulnerability, end_of_life or "all"
  resolved: number;
  mean_days: number | null;
  median_days: number | null;
}

export interface OutcomeSLA {
  priority: string;
  fix_days: number;
  resolved: number;
  resolved_within_sla: number;
  rate: number | null;
  open_active: number;
  open_overdue: number;
}

export interface OutcomeReopen {
  finding_id: number;
  key: string;
  component: string;
  version: string;
  asset_id: number;
  asset_name: string;
  reopened_at: string;
  previous_resolution: string;
}

export interface OutcomeFailure {
  action_id: number;
  plan_id: number;
  asset_id: number;
  asset_name: string;
  package: string;
  from_version: string;
  to_version: string;
  status: string;
  error: string;
  at: string;
}

export interface OutcomesReport {
  from: string;
  to: string;
  generated_at: string;
  events_since: string | null;
  resolved: number;
  time_to_remedy: OutcomeTiming[] | null;
  causes: { cause: string; evidence: string; count: number }[] | null;
  sla: OutcomeSLA[] | null;
  reopened: {
    events: number;
    findings: number;
    resolution_events: number;
    later_reopened: number;
    rate: number | null;
    recent: OutcomeReopen[] | null;
    recent_limit: number;
  };
  open: {
    active: number;
    overdue: number;
    excepted: number;
    stale_asset: number;
    /** Open findings by evidence state: confirmed, needs_validation, stale, stale_intelligence, unknown. */
    by_evidence?: Record<string, number>;
  };
  remediation: {
    plans: Record<string, number> | null;
    actions: Record<string, number> | null;
    finished: number;
    verified: number;
    failed: number;
    rolled_back: number;
    success_rate: number | null;
    rollback_actions: Record<string, number> | null;
    recent_failures: OutcomeFailure[] | null;
  } | null;
}

export interface Feed {
  name: string;
  kind: "vulnerability" | "release" | "lifecycle" | string;
  enabled: boolean;
  auto?: boolean;
  refresh_minutes: number;
  stale_after_minutes: number;
  cursor?: string;
  records: number;
  last_attempt: string | null;
  last_success: string | null;
  last_error: string;
  last_changed: number;
  stale: boolean;
}

export interface EvaluationGap {
  component_id: number;
  purl_key: string;
  reason: string;
  asset_count: number;
  updated_at: string;
  /** unsupported: no source exists; not_evaluated: a source exists but could not be used. */
  coverage: "unsupported" | "not_evaluated";
}

export interface Release {
  component_id: number;
  latest: string;
  latest_stable: string;
  latest_published: string | null;
  yanked?: Record<string, string>; // withdrawn (yanked, retracted, unlisted) version -> reason
  deprecated: string;
  source: string;
  source_url: string;
  checked_at: string;
  last_error: string;
}

export interface LifecycleCycle {
  product: string;
  product_label: string;
  cycle: string;
  label: string;
  release_date: string | null;
  lts: boolean;
  support_until: string | null;
  eol_until: string | null;
  is_eol: boolean;
  latest: string;
  latest_date: string | null;
  link: string;
}

export interface ComponentIntel {
  component: Component;
  release?: Release | null;
  lifecycle?: { product: string; cycles: LifecycleCycle[] | null } | null;
}

/**
 * Path segment for a feed name ("osv:Rocky Linux"). Spaces etc. are escaped,
 * but ":" is left literal: an escaped %3A makes Go keep a RawPath, and chi
 * then passes the still-escaped name to the handler (404).
 */
export function feedPath(name: string): string {
  return encodeURIComponent(name).replace(/%3A/gi, ":");
}

/** Only http(s) URLs from feeds are ever rendered as links. */
export function safeHttpUrl(u: string | null | undefined): string | null {
  if (!u) return null;
  try {
    const url = new URL(u);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}

// --- Stage 3: priority, workflow, incidents, notifications

export const PRIORITIES = ["P1", "P2", "P3", "P4"] as const;
export type Priority = (typeof PRIORITIES)[number];
export const FINDING_STATES = ["new", "acknowledged", "in_progress", "suppressed", "risk_accepted"] as const;
export type FindingState = (typeof FINDING_STATES)[number];
export const INCIDENT_KINDS = ["vulnerability", "end_of_life", "feed", "collection", "coverage", "platform"] as const;
export const SYSTEM_INCIDENT_KINDS = ["feed", "collection", "coverage", "platform"];

export interface PriorityFactor {
  name: string;
  points: number;
  detail: string;
}

export type FindingActionName =
  | "acknowledge"
  | "start"
  | "reset"
  | "assign"
  | "comment"
  | "suppress"
  | "accept_risk"
  | "reopen";

export interface FindingActionRequest {
  action: FindingActionName;
  note?: string;
  until?: string; // RFC 3339
  mitigation?: string; // suppress / accept_risk only, max 2000 chars
  user_id?: number; // 0 clears
  team_id?: number; // 0 clears
  ids?: number[]; // bulk only
}

export interface ActionResult {
  applied: number;
  failed: string[] | null;
}

export interface FindingEvent {
  id: number;
  at: string;
  actor_type: string;
  actor_name: string;
  action: string;
  from_state: string;
  to_state: string;
  note: string;
  detail: Record<string, unknown> | null;
}

export interface IncidentDetailInfo {
  assets?: string[];
  environments?: string[];
  components?: string[];
  fixed_versions?: string[];
  known_exploited?: boolean;
  severity?: string;
  // system incidents
  last_error?: string;
  last_success?: string;
  asset_id?: number;
  [k: string]: unknown;
}

export interface Incident {
  id: number;
  kind: string;
  key: string;
  owner_team_id: number | null;
  owner_team: string;
  title: string;
  priority: Priority | "";
  sos: boolean;
  status: "open" | "resolved" | string;
  state: string;
  finding_count: number;
  asset_count: number;
  detail: IncidentDetailInfo | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  notified_priority: string;
  notified_at: string | null;
  escalation_level: number;
  /** Tracker issues (Jira) that follow this incident. */
  issues?: IssueRef[] | null;
}

export interface IssueRef {
  tracker: string;
  key: string;
  url: string;
  channel_id: number | null;
}

export interface Delivery {
  id: number;
  channel_id: number;
  channel_name: string;
  channel_kind: string;
  route_id: number | null;
  incident_id: number | null;
  event: string;
  dedupe_key: string;
  payload: unknown;
  status: "pending" | "sent" | "failed" | "held" | string;
  attempts: number;
  next_attempt: string;
  last_error: string;
  created_at: string;
  sent_at: string | null;
}

export interface IncidentResponse {
  incident: Incident;
  findings: Finding[] | null;
  deliveries?: Delivery[] | null;
}

export const CHANNEL_KINDS = ["email", "slack", "teams", "webhook", "jira"] as const;
export type ChannelKind = (typeof CHANNEL_KINDS)[number];

export interface ChannelConfig {
  host?: string;
  port?: number;
  username?: string;
  from?: string;
  to?: string[];
  tls?: "starttls" | "tls" | "none" | "";
  url?: string;
  // jira (url is the site's base URL, username the Cloud account email)
  deployment?: "cloud" | "datacenter" | "";
  project?: string;
  issue_type?: string;
  labels?: string[];
  priorities?: Partial<Record<Priority, string>>;
  resolve_transition?: string;
}

export interface Channel {
  id: number;
  kind: ChannelKind | string;
  name: string;
  config: ChannelConfig | null;
  secret_ref: string;
  enabled: boolean;
  created_at: string;
  last_ok_at: string | null;
  last_error: string;
}

export interface Route {
  id: number;
  name: string;
  channel_id: number;
  enabled: boolean;
  min_priority: Priority;
  sos_only: boolean;
  kinds: string[] | null;
  environments: string[] | null;
  team_ids: number[] | null;
  escalation: boolean;
  send_resolved: boolean;
  quiet_start: string;
  quiet_end: string;
  timezone: string;
  max_per_hour: number;
  created_at?: string;
  /** urgent_summary: urgent alerts right away and a daily summary; daily or weekly: summary only. */
  mode: RouteMode;
  /** "HH:MM" in `timezone`. */
  summary_time: string;
  /** Weekday of the weekly summary, e.g. "monday". */
  summary_day: string;
  /** End of the period the last summary covered (read-only). */
  last_summary_at?: string;
}

export type RouteMode = "urgent_summary" | "daily" | "weekly";
export const ROUTE_MODES: RouteMode[] = ["urgent_summary", "daily", "weekly"];
export const WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"] as const;

export interface SOSRule {
  name: string;
  min_priority?: Priority;
  known_exploited?: boolean;
  production?: boolean;
  internet_exposed?: boolean;
  min_severity?: string;
  fix_available?: boolean;
}

export interface RiskPolicy {
  severity_base: Record<string, number>;
  eol_base: number;
  known_exploited: number;
  internet_exposed: number;
  exposure_unknown: number;
  production: number;
  /** Added when an asset has no environment; at most `production`. */
  environment_unknown: number;
  fix_available: number;
  overdue: number;
  dev_dependency: number;
  criticality: Record<string, number>;
  needs_validation_multiplier: number;
  stale_multiplier: number;
  production_environments: string[] | null;
  thresholds: { p1: number; p2: number; p3: number };
  sla: Record<string, { ack_hours: number; fix_days: number }>;
  sos_rules: SOSRule[] | null;
  /** Longest suppression / risk acceptance in days (1–730; 0 means the default, 365). */
  exception_max_days?: number;
}

export const DEFAULT_EXCEPTION_MAX_DAYS = 365;

/** Who last changed a policy and when, from the audit log. */
export interface PolicyChangeRef {
  at: string;
  actor_type: string;
  actor_name: string;
  version: string;
  previous_version: string;
  changed: string[];
}

/** GET /risk-policy */
export interface RiskPolicyResponse {
  policy: RiskPolicy;
  default: RiskPolicy;
  version: string;
  /** Null when the policy has never been changed (the defaults apply). */
  last_change?: PolicyChangeRef | null;
}

/** One finding whose priority or SOS a proposed risk policy changes. */
export interface RiskPreviewFinding {
  id: number;
  key: string;
  title: string;
  asset_id: number;
  asset_name: string;
  before: string;
  after: string;
  score_before: number;
  score_after: number;
  sos_before: boolean;
  sos_after: boolean;
  factors: { name: string; before: number; after: number }[];
}

/** POST /risk-policy/preview: the proposed policy's effect, nothing saved. */
export interface RiskPolicyPreview {
  current_version: string;
  proposed_version: string;
  changed_fields: string[];
  findings: number;
  before: Record<string, number>;
  after: Record<string, number>;
  sos_before: number;
  sos_after: number;
  priority_changed: number;
  raised: number;
  lowered: number;
  sos_changed: number;
  score_changed: number;
  stored_differs: number;
  sample: RiskPreviewFinding[];
  sample_limit: number;
}

export interface DirectoryUser {
  id: number;
  email: string;
  name: string;
}

// --- Stage 4: controlled remediation

export const REMEDIATION_TARGETS = ["host_package", "repository"] as const;
export const HOST_ECOSYSTEMS = ["deb", "rpm", "apk"];
export const REPO_ECOSYSTEMS = ["npm", "composer"];
export const CHANGE_TYPES = ["distro", "patch", "minor", "major"] as const;
export const PLAN_STATUSES = [
  "proposed",
  "approved",
  "in_progress",
  "succeeded",
  "failed",
  "partially_failed",
  "rejected",
  "cancelled",
] as const;

/** One package on one asset whose remediation eligibility a proposed policy changes. */
export interface PolicyPreviewPackage {
  asset_id: number;
  asset_name: string;
  environment: string;
  package: string;
  from_version: string;
  to_version: string;
  change_type: string;
  priority: string;
  finding_keys: string[] | null;
  /** The policy that authorises it before and after ("" for none). */
  before_policy: string;
  after_policy: string;
  /** Why the proposed policy no longer authorises it. */
  reason?: string;
}

/** POST /remediation/policies/preview: what saving the policy would change, nothing saved. */
export interface RemediationPolicyPreview {
  candidates: number;
  eligible_before: number;
  eligible_after: number;
  assets_before: number;
  assets_after: number;
  gained: number;
  gained_from_none: number;
  lost: number;
  lost_to_none: number;
  gained_assets: number;
  lost_assets: number;
  gained_sample: PolicyPreviewPackage[];
  lost_sample: PolicyPreviewPackage[];
  sample_limit: number;
}

export interface RemediationPolicy {
  id: number;
  name: string;
  description: string;
  enabled: boolean;
  target: "host_package" | "repository";
  ecosystems: string[] | null;
  components: string[] | null;
  environments: string[] | null;
  team_ids: number[] | null;
  asset_tags: string[] | null;
  change_types: string[] | null;
  allow_major: boolean;
  min_priority: string;
  only_with_findings: boolean;
  approval: "required" | "automatic";
  window_days: number[] | null;
  window_start: string;
  window_end: string;
  timezone: string;
  canary_count: number;
  soak_minutes: number;
  max_concurrent: number;
  health_units: string[] | null;
  auto_rollback: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface Plan {
  id: number;
  policy_id: number | null;
  policy_name: string;
  target: string;
  component_id: number;
  purl_key: string;
  package: string;
  target_version: string;
  change_type: string;
  finding_keys: string[] | null;
  status: string;
  stage: string;
  rollback: string;
  created_by: string;
  approved_by: number | null;
  approved_at: string | null;
  decision_note: string;
  created_at: string;
  updated_at: string;
  canary_done_at: string | null;
  action_counts: Record<string, number> | null;
  from_versions?: string[] | null;
  environments?: string[] | null;
  approved_by_email?: string;
  repository_url?: string;
}

export interface RemediationAction {
  id: number;
  plan_id: number;
  asset_id: number;
  asset_name: string;
  environment: string;
  inventory_id: number | null;
  kind: string;
  package: string;
  manager: string;
  from_version: string;
  to_version: string;
  stage: string;
  status: string;
  dry_run: { output?: string } | null;
  result: { output?: string } | null;
  error: string;
  health: Record<string, string> | null;
  attempts: number;
  created_at: string;
  released_at: string | null;
  dispatched_at: string | null;
  applied_at: string | null;
  verified_at: string | null;
  deadline: string | null;
}

export interface PlanResponse {
  plan: Plan;
  actions: RemediationAction[] | null;
}

// --- Stage 5: plugins

export interface PluginConfigField {
  name: string;
  type: "string" | "number" | "boolean" | "string_list" | string;
  required: boolean;
  description: string;
}

export interface PluginMetadata {
  id: string;
  name: string;
  version: string;
  maintainer: string;
  license: string;
  homepage?: string;
  description: string;
  protocol_version: string;
  schema_version: string;
  capabilities: string[] | null;
  permissions: string[] | null;
  credentials: string[] | null;
  network_access: string[] | null;
  config_schema: PluginConfigField[] | null;
  default_frequency?: string;
  rate_limits?: string;
  known_limitations: string[] | null;
}

export interface InstalledPlugin {
  name: string;
  metadata?: PluginMetadata | null;
  error?: string;
}

export interface PluginList extends List<InstalledPlugin> {
  enabled: boolean;
}

// --- Action plan (fix groups)

export const FIX_GROUP_KINDS = ["security_updates", "old_kernels", "release_upgrade", "end_of_life", "package_upgrade", "no_fix"] as const;
export type FixGroupKind = (typeof FIX_GROUP_KINDS)[number];

export interface FixGroup {
  id: string; // e.g. "12:security_updates"
  kind: FixGroupKind | string;
  title: string;
  action: string;
  asset_id: number;
  asset_name: string;
  asset_kind: string;
  environment: string;
  component?: string;
  from_version?: string;
  to_version?: string;
  packages: string[] | null;
  package_count: number;
  finding_count: number;
  /** Distinct CVE/advisory keys in the group: the number people think in. */
  unique_issues?: number;
  by_priority: Record<string, number> | null;
  by_severity: Record<string, number> | null;
  top_priority: string;
  sos: boolean;
  known_exploited: number;
  needs?: string;
  effort: "low" | "medium" | "high" | string;
  note?: string;
  /** Package upgrades: the newest stable release in the major line at or above to_version, from release data. */
  recommended_version?: string;
  change_type?: string;
  requires_major?: boolean;
  recommended_yanked?: boolean;
  rationale?: string[] | null;
}

export interface FixGroupDetail {
  group: FixGroup;
  /** Paged with ?limit=&offset= on GET /fix-groups/{id}. */
  findings: List<Finding> | null;
}

export interface FixGroupSummary {
  groups: number;
  findings: number;
  by_kind: Record<string, { groups: number; findings: number }> | null;
  sos: number;
  fixable_findings: number;
  sos_findings?: number;
  /** Distinct CVE/advisory keys across all groups, when the server provides it. */
  unique_issues?: number;
  /** What needs a person now, and why the other groups are left out of that view. */
  focus?: FixFocus;
}

/** Buckets of GET /fix-groups?bucket=, mirrors store.FixBuckets. */
export const FIX_BUCKETS = ["focus", "no_fix", "old_kernels", "non_production", "lower_priority"] as const;
export type FixBucket = (typeof FIX_BUCKETS)[number];

export interface FixFocus {
  groups: number;
  findings: number;
  hidden: Partial<Record<FixBucket, { groups: number; findings: number }>> | null;
  assets: { asset_id: number; asset_name: string; groups: number; findings: number }[] | null;
}

// --- Stage 6: evidence report

export interface ReportException {
  finding_id: number;
  key: string;
  component: string;
  version: string;
  asset_id: number;
  asset_name: string;
  severity: string;
  priority: string;
  state: string;
  reason: string;
  mitigation: string;
  until: string | null;
  /** Evidence state: confirmed, needs_validation, stale, stale_intelligence, unknown. */
  verification?: string;
}

export interface ReportDrift {
  replica_id: number;
  replica_name: string;
  primary_id: number;
  primary_name: string;
  counts: Record<string, number> | null;
}

/** GET /reports/evidence: patch-management evidence for a period. */
export interface EvidenceReport {
  generated_at: string;
  from: string;
  to: string;
  assets: {
    total: number;
    by_kind: Record<string, number> | null;
    by_status: Record<string, number> | null;
    reboot_required: number;
  };
  coverage: { components: number; evaluation_gaps: number; coverage_problems: number };
  open: {
    total: number;
    by_severity: Record<string, number> | null;
    by_priority: Record<string, number> | null;
    known_exploited: number;
    end_of_life: number;
    overdue: number;
    overdue_by_priority: Record<string, number> | null;
    /** Open findings by evidence state (EVIDENCE_STATE_LABEL). */
    by_evidence?: Record<string, number> | null;
  };
  resolved: {
    total: number;
    within_sla: number;
    median_days: number | null;
    median_days_by_priority: Record<string, number> | null;
  };
  exceptions: ReportException[] | null;
  drift: ReportDrift[] | null;
}

// --- Enrollment: one-time install codes for new servers (admin)

export interface Enrollment {
  id: number;
  prefix: string;
  label: string;
  environment: string;
  app_dirs: string[];
  discover_apps: boolean;
  uses_left: number;
  created_by: string;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

/** POST /enrollments: the code is returned only here, once. */
export interface EnrollmentCreated {
  enrollment: Enrollment;
  code: string;
}

// --- transport

export class ApiError extends Error {
  status: number;
  code: string;
  details: string[];
  constructor(status: number, code: string, message: string, details: string[] = []) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

/** Called on any 401 so the app can drop back to the login screen. */
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: (() => void) | null) {
  onUnauthorized = fn;
}

type Query = Record<string, string | number | boolean | undefined | null>;

export function qs(q?: Query): string {
  if (!q) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === "") continue;
    p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

async function request<T>(method: string, path: string, body?: unknown, opts?: { quiet401?: boolean }): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") headers["X-Stackurity-CSRF"] = "1";
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    throw new ApiError(0, "network", "Could not reach the Stackurity server. Check that it is running.");
  }
  if (res.status === 204) return undefined as T;
  let data: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string; details?: string[] } } | null)?.error;
    if (res.status === 401 && !opts?.quiet401 && onUnauthorized) onUnauthorized();
    throw new ApiError(
      res.status,
      err?.code ?? "http_" + res.status,
      err?.message ?? `Request failed (${res.status} ${res.statusText})`,
      err?.details ?? [],
    );
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, q?: Query) => request<T>("GET", path + qs(q)),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
  del: <T = void>(path: string, body?: unknown) => request<T>("DELETE", path, body),

  meta: () => request<Meta>("GET", "/meta"),
  me: () => request<Me>("GET", "/auth/me", undefined, { quiet401: true }),
  login: (email: string, password: string) =>
    request<User>("POST", "/auth/login", { email, password }, { quiet401: true }),
  setup: (b: { setup_token: string; email: string; name: string; password: string }) =>
    request<User>("POST", "/setup", b, { quiet401: true }),
  logout: () => request<void>("POST", "/auth/logout", undefined, { quiet401: true }),
};

/**
 * Polls GET /jobs/{id} until the job is done or failed (or the timeout
 * passes). Resolves with the final job, or null on timeout.
 */
export async function waitForJob(id: number, opts: { intervalMs?: number; timeoutMs?: number; signal?: AbortSignal } = {}): Promise<Job | null> {
  const interval = opts.intervalMs ?? 2000;
  const deadline = Date.now() + (opts.timeoutMs ?? 10 * 60_000);
  while (Date.now() < deadline) {
    if (opts.signal?.aborted) return null;
    const j = await api.get<Job>(`/jobs/${id}`);
    if (j.done_at || j.failed_at) return j;
    await new Promise((r) => setTimeout(r, interval));
  }
  return null;
}
