import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, ApiError, atLeast, setUnauthorizedHandler, type Feature, type Me, type Meta, type UserRole } from "./api";

type State =
  | { phase: "loading" }
  | { phase: "error"; error: ApiError }
  | { phase: "setup"; meta: Meta }
  | { phase: "login"; meta: Meta }
  | { phase: "ready"; meta: Meta; me: Me };

interface AuthValue {
  state: State;
  me: Me | null;
  meta: Meta | null;
  can: (min: UserRole) => boolean;
  /** Whether this workspace's plan includes a paid feature. */
  has: (f: Feature) => boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>({ phase: "loading" });

  const refresh = useCallback(async () => {
    let meta: Meta;
    try {
      meta = await api.meta();
    } catch (e) {
      setState({ phase: "error", error: e as ApiError });
      return;
    }
    if (meta.setup_required) {
      setState({ phase: "setup", meta });
      return;
    }
    try {
      const me = await api.me();
      setState({ phase: "ready", meta, me });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setState({ phase: "login", meta });
      else setState({ phase: "error", error: e as ApiError });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Any 401 during normal use (expired session) returns to the login screen.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setState((s) => (s.phase === "ready" ? { phase: "login", meta: s.meta } : s));
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      await refresh();
    }
  }, [refresh]);

  const value = useMemo<AuthValue>(() => {
    const me = state.phase === "ready" ? state.me : null;
    const meta = "meta" in state ? state.meta : null;
    return { state, me, meta, can: (min) => atLeast(me?.role, min), has: (f) => Boolean(me?.features?.includes(f)), refresh, logout };
  }, [state, refresh, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const v = useContext(AuthContext);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
