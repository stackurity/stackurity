/**
 * Which project a new install code puts its servers in.
 *
 * A code made without a project enrolls servers that are in no project:
 * anyone looking at a project in the switcher does not see them, and people
 * with access through projects only never do. So the Add server forms
 * pre-select the project the person is looking at, or the only project the
 * workspace has, and otherwise ask.
 */

/** The select's value: "" not chosen yet, "none" no project, or a project id. */
export type ProjectChoice = "" | "none" | `${number}`;

export interface ProjectOption {
  id: number;
  name: string;
  archived_at?: string | null;
}

/** Projects a code can add servers to: the active (not archived) ones. */
export function openProjects<P extends ProjectOption>(projects: readonly P[]): P[] {
  return projects.filter((p) => !p.archived_at);
}

/**
 * The project pre-selected for a new code: the one chosen in the switcher,
 * else the workspace's only project, else none (0).
 */
export function defaultEnrollProject(activeId: number, projects: readonly ProjectOption[]): number {
  const open = openProjects(projects);
  if (activeId > 0 && open.some((p) => p.id === activeId)) return activeId;
  if (open.length === 1) return open[0].id;
  return 0;
}

/**
 * The select's starting value. With no projects there is nothing to choose
 * ("none"); with projects and nothing to pre-select, the person must choose ("").
 */
export function initialProjectChoice(activeId: number, projects: readonly ProjectOption[]): ProjectChoice {
  if (openProjects(projects).length === 0) return "none";
  const id = defaultEnrollProject(activeId, projects);
  return id > 0 ? `${id}` : "";
}

/** The project_id to send: 0 for no project. */
export function choiceProjectId(choice: ProjectChoice): number {
  if (choice === "" || choice === "none") return 0;
  const n = Number(choice);
  return Number.isInteger(n) && n > 0 ? n : 0;
}

/** The name of a code's project, for lists and the install command card. */
export function projectName(id: number | null | undefined, projects: readonly ProjectOption[]): string {
  if (!id) return "";
  return projects.find((p) => p.id === id)?.name ?? `Project #${id}`;
}

/**
 * Where an enrolled server shows up, in one sentence for the install
 * command card.
 */
export function whereServerAppears(id: number | null | undefined, projects: readonly ProjectOption[]): string {
  const name = projectName(id, projects);
  if (name) return `The server appears under Assets in the project ${name} within a minute; applications on it are added to the project too.`;
  if (openProjects(projects).length === 0) return "The server appears under Assets within a minute; applications appear as their own assets linked to it.";
  return "The server appears under Assets within a minute, in no project: switch the project picker to All projects to see it, then add it to a project from Assets → Not in a project.";
}
