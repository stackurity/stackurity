/**
 * The Add user form's state as data: who they are, and what they can see.
 * Nothing is chosen for the admin: the form cannot be sent until "What can
 * they see?" and every permission under it are picked. Free of React and of
 * imports other than types so node --test can load it (userAccess.test.ts
 * drives every control through these actions).
 */
import type { UserRole } from "./api";

export type Scope = "" | "all" | "specific";
/** "project": every asset of the project, including later ones; "assets": the ones ticked. */
export type ProjectMode = "" | "project" | "assets";

export interface ProjectPick {
  projectId: number;
  mode: ProjectMode;
  /** The permission on the whole project (mode "project"). */
  role: UserRole | "";
  /** Ticked assets and the permission on each (mode "assets"), in the order ticked. */
  assets: { assetId: number; role: UserRole | "" }[];
}

export interface AddUserState {
  name: string;
  email: string;
  phone: string;
  password: string;
  scope: Scope;
  /** The permission on everything (scope "all"). */
  allRole: UserRole | "";
  projects: ProjectPick[];
}

export const EMPTY: AddUserState = { name: "", email: "", phone: "", password: "", scope: "", allRole: "", projects: [] };

export type Action =
  | { type: "field"; field: "name" | "email" | "phone" | "password"; value: string }
  | { type: "scope"; scope: "all" | "specific" }
  | { type: "allRole"; role: UserRole }
  | { type: "addProject"; projectId: number }
  | { type: "removeProject"; projectId: number }
  | { type: "projectMode"; projectId: number; mode: "project" | "assets" }
  | { type: "projectRole"; projectId: number; role: UserRole }
  | { type: "toggleAsset"; projectId: number; assetId: number; checked: boolean }
  | { type: "assetRole"; projectId: number; assetId: number; role: UserRole };

/** Every action the form's controls dispatch; the tests cover each one. */
export const ACTION_TYPES: Action["type"][] = [
  "field", "scope", "allRole", "addProject", "removeProject", "projectMode", "projectRole", "toggleAsset", "assetRole",
];

const SPECIFIC: readonly string[] = ["viewer", "engineer", "security"];
const ALL: readonly string[] = ["viewer", "engineer", "security", "admin"];

function mapProject(s: AddUserState, id: number, f: (p: ProjectPick) => ProjectPick): AddUserState {
  return { ...s, projects: s.projects.map((p) => (p.projectId === id ? f(p) : p)) };
}

export function reduce(s: AddUserState, a: Action): AddUserState {
  switch (a.type) {
    case "field":
      return { ...s, [a.field]: a.value };
    case "scope":
      // Switching keeps the other choice, so switching back loses nothing;
      // only the chosen scope is sent.
      return { ...s, scope: a.scope };
    case "allRole":
      return ALL.includes(a.role) ? { ...s, allRole: a.role } : s;
    case "addProject":
      if (a.projectId <= 0 || s.projects.some((p) => p.projectId === a.projectId)) return s;
      return { ...s, projects: [...s.projects, { projectId: a.projectId, mode: "", role: "", assets: [] }] };
    case "removeProject":
      return { ...s, projects: s.projects.filter((p) => p.projectId !== a.projectId) };
    case "projectMode":
      return mapProject(s, a.projectId, (p) => ({ ...p, mode: a.mode }));
    case "projectRole":
      return SPECIFIC.includes(a.role) ? mapProject(s, a.projectId, (p) => ({ ...p, role: a.role })) : s;
    case "toggleAsset":
      return mapProject(s, a.projectId, (p) => {
        const has = p.assets.some((x) => x.assetId === a.assetId);
        if (a.checked === has) return p;
        return { ...p, assets: a.checked ? [...p.assets, { assetId: a.assetId, role: "" }] : p.assets.filter((x) => x.assetId !== a.assetId) };
      });
    case "assetRole":
      if (!SPECIFIC.includes(a.role)) return s;
      return mapProject(s, a.projectId, (p) => ({ ...p, assets: p.assets.map((x) => (x.assetId === a.assetId ? { ...x, role: a.role } : x)) }));
  }
}

/** Mirrors store.NormalizePhone: "" when fine (or empty), else why not. */
export function phoneProblem(phone: string): string {
  const p = phone.trim().split(/\s+/).join(" ");
  if (!p) return "";
  if (p.length > 32) return "Phone is limited to 32 characters.";
  if (!/^\+?[0-9 ().-]*$/.test(p)) return "Phone may contain digits, a leading +, spaces, dots, dashes and brackets only.";
  const digits = p.replace(/\D/g, "").length;
  if (digits < 6 || digits > 15) return "Phone must have 6 to 15 digits.";
  return "";
}

/**
 * Everything still missing or wrong, in the order of the form. The form
 * can be sent when this is empty. names: project id → name, for messages.
 */
export function problems(s: AddUserState, names: Record<number, string> = {}): string[] {
  const out: string[] = [];
  const email = s.email.trim();
  if (!email) out.push("Enter their email.");
  else if (!/^[^\s@]+@[^\s@]+$/.test(email)) out.push("Enter a valid email.");
  const ph = phoneProblem(s.phone);
  if (ph) out.push(ph);
  if (s.password && s.password.length < 12) out.push("The initial password needs at least 12 characters.");
  if (s.name.trim().length > 200) out.push("The name is limited to 200 characters.");
  if (s.scope === "") {
    out.push("Choose what they can see: all projects and assets, or specific ones.");
    return out;
  }
  if (s.scope === "all") {
    if (!s.allRole) out.push("Choose their permission on all projects and assets.");
    return out;
  }
  if (s.projects.length === 0) out.push("Add at least one project.");
  for (const p of s.projects) {
    const n = names[p.projectId] ?? `project ${p.projectId}`;
    if (p.mode === "") out.push(`${n}: choose all its assets, or chosen assets.`);
    else if (p.mode === "project" && !p.role) out.push(`${n}: choose a permission.`);
    else if (p.mode === "assets") {
      if (p.assets.length === 0) out.push(`${n}: tick at least one asset.`);
      const missing = p.assets.filter((x) => !x.role).length;
      if (missing) out.push(`${n}: choose a permission for ${missing === 1 ? "the ticked asset" : `${missing} ticked assets`}.`);
    }
  }
  return out;
}

export interface GrantBody {
  project_id?: number;
  asset_id?: number;
  role: UserRole;
}

export interface CreateUserBody {
  email: string;
  name: string;
  phone: string;
  password: string;
  role: UserRole | "none";
  grants?: GrantBody[];
}

const RANK: Record<string, number> = { viewer: 1, engineer: 2, security: 3, admin: 4 };

/** The POST /users body; call only when problems() is empty. */
export function toRequest(s: AddUserState): CreateUserBody {
  const base = { email: s.email.trim(), name: s.name.trim(), phone: s.phone.trim().split(/\s+/).join(" "), password: s.password };
  if (s.scope === "all") return { ...base, role: s.allRole as UserRole };
  const grants: GrantBody[] = [];
  const assetAt = new Map<number, number>();
  for (const p of s.projects) {
    if (p.mode === "project") grants.push({ project_id: p.projectId, role: p.role as UserRole });
    if (p.mode !== "assets") continue;
    for (const x of p.assets) {
      // An asset ticked under two projects is one grant, with the higher permission.
      const i = assetAt.get(x.assetId);
      if (i === undefined) {
        assetAt.set(x.assetId, grants.length);
        grants.push({ asset_id: x.assetId, role: x.role as UserRole });
      } else if (RANK[x.role] > RANK[grants[i].role]) grants[i] = { ...grants[i], role: x.role as UserRole };
    }
  }
  return { ...base, role: "none", grants };
}

/** What the admin is about to give, in one line above the button. */
export function preview(s: AddUserState, labels: Record<string, string>): string {
  if (s.scope === "all") return s.allRole ? `All projects and assets — ${labels[s.allRole] ?? s.allRole}.` : "";
  if (s.scope !== "specific") return "";
  const req = toRequest(s);
  const g = req.grants ?? [];
  const p = g.filter((x) => x.project_id).length;
  const a = g.filter((x) => x.asset_id).length;
  const parts: string[] = [];
  if (p) parts.push(`${p} whole project${p === 1 ? "" : "s"} (and assets added to ${p === 1 ? "it" : "them"} later)`);
  if (a) parts.push(`${a} chosen asset${a === 1 ? "" : "s"}`);
  return parts.length ? `Only ${parts.join(" and ")}.` : "";
}
