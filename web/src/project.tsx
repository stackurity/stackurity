import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router";
import { api, setActiveProject, type Project } from "./api";
import { useAuth } from "./auth";

/**
 * The project chosen in the switcher. It scopes Home, Fixes, Assets and
 * Activity (the server narrows what they read). The choice is in the URL
 * (?project=ID, so a link opens the same view) and remembered for the
 * person, so the next visit starts where they left.
 */
interface ProjectValue {
  /** 0: all projects. */
  projectId: number;
  project: Project | null;
  projects: Project[];
  choose: (id: number) => void;
}

const ProjectContext = createContext<ProjectValue>({ projectId: 0, project: null, projects: [], choose: () => {} });

function fromURL(search: string): number | null {
  const v = new URLSearchParams(search).get("project");
  if (v === null) return null;
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 ? n : 0;
}

export function ProjectProvider({ children }: { children: ReactNode }) {
  const { me } = useAuth();
  const { pathname, search, hash } = useLocation();
  const navigate = useNavigate();
  const projects = useMemo(() => me?.projects ?? [], [me]);
  const known = useCallback((id: number) => id === 0 || projects.some((p) => p.id === id), [projects]);

  const [projectId, setProjectId] = useState<number>(() => {
    const u = fromURL(search);
    const want = u ?? me?.default_project_id ?? 0;
    const id = known(want) ? want : 0;
    setActiveProject(id);
    return id;
  });

  // A project removed or archived since: back to all projects.
  useEffect(() => {
    if (!known(projectId)) {
      setActiveProject(0);
      setProjectId(0);
    }
  }, [known, projectId]);

  // A link with ?project= switches to it.
  useEffect(() => {
    const u = fromURL(search);
    if (u !== null && u !== projectId && known(u)) {
      setActiveProject(u);
      setProjectId(u);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  // Keep the choice in the address, so it can be shared and bookmarked.
  useEffect(() => {
    const q = new URLSearchParams(search);
    const have = q.get("project");
    const want = projectId > 0 ? String(projectId) : null;
    if (have === want) return;
    if (want) q.set("project", want);
    else q.delete("project");
    const s = q.toString();
    navigate(`${pathname}${s ? `?${s}` : ""}${hash}`, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname, search, projectId]);

  const choose = useCallback(
    (id: number) => {
      const next = known(id) ? id : 0;
      setActiveProject(next);
      setProjectId(next);
      void api.put("/auth/default-project", { project_id: next }).catch(() => {});
    },
    [known],
  );

  const value = useMemo<ProjectValue>(
    () => ({ projectId, project: projects.find((p) => p.id === projectId) ?? null, projects, choose }),
    [projectId, projects, choose],
  );
  return <ProjectContext.Provider value={value}>{children}</ProjectContext.Provider>;
}

export function useProject(): ProjectValue {
  return useContext(ProjectContext);
}
