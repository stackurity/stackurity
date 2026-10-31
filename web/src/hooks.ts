import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { confirmAction } from "./components/ConfirmDialog";
import { api, ApiError, DEFAULT_EXCEPTION_MAX_DAYS, waitForJob, type Facets, type Queued, type RiskPolicy } from "./api";

export interface Loaded<T> {
  data: T | undefined;
  error: ApiError | null;
  loading: boolean;
  reload: () => void;
}

/**
 * Runs an async loader whenever deps change, ignoring stale responses.
 * Keeps the previous data while reloading so tables do not flicker.
 */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]): Loaded<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const seq = useRef(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    const id = ++seq.current;
    setLoading(true);
    fnRef
      .current()
      .then((d) => {
        if (id !== seq.current) return;
        setData(d);
        setError(null);
      })
      .catch((e: unknown) => {
        if (id !== seq.current) return;
        setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
      })
      .finally(() => {
        if (id === seq.current) setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}

/** Wraps a mutation with pending/error state. */
export function useAction() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setPending(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
      return undefined;
    } finally {
      setPending(false);
    }
  }, []);
  return { pending, error, run, clear: () => setError(null) };
}

/** Debounces a fast-changing value (search boxes). */
export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

// --- background jobs

export type JobState =
  | { phase: "idle" }
  | { phase: "running"; jobId: number; label: string }
  | { phase: "done"; label: string }
  | { phase: "failed"; label: string; error: string }
  | { phase: "already"; label: string }
  | { phase: "timeout"; label: string };

/**
 * Starts work that the server queues as a job ({job_id, queued}), then polls
 * GET /jobs/{id} until it finishes and calls onFinished.
 */
export function useJobRunner(onFinished?: () => void) {
  const [state, setState] = useState<JobState>({ phase: "idle" });
  const [error, setError] = useState<ApiError | null>(null);
  const abort = useRef<AbortController | null>(null);
  const finished = useRef(onFinished);
  finished.current = onFinished;

  useEffect(() => () => abort.current?.abort(), []);

  const start = useCallback(async (label: string, enqueue: () => Promise<Queued>) => {
    setError(null);
    abort.current?.abort();
    const ctl = new AbortController();
    abort.current = ctl;
    let q: Queued;
    try {
      q = await enqueue();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
      setState({ phase: "idle" });
      return;
    }
    if (!q.queued || !q.job_id) {
      setState({ phase: "already", label });
      return;
    }
    setState({ phase: "running", jobId: q.job_id, label });
    try {
      const j = await waitForJob(q.job_id, { signal: ctl.signal });
      if (ctl.signal.aborted) return;
      if (!j) setState({ phase: "timeout", label });
      else if (j.failed_at) setState({ phase: "failed", label, error: j.last_error || "job failed" });
      else setState({ phase: "done", label });
      finished.current?.();
    } catch (e) {
      if (ctl.signal.aborted) return;
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
      setState({ phase: "idle" });
    }
  }, []);

  return { state, error, start, busy: state.phase === "running", reset: () => setState({ phase: "idle" }) };
}

// --- facets (environments, kinds, component types) shared by filter bars

let facetsCache: Promise<Facets> | null = null;
export function useFacets(): Facets | undefined {
  const r = useLoad(() => {
    if (!facetsCache) facetsCache = api.get<Facets>("/facets").catch((e) => {
      facetsCache = null;
      throw e;
    });
    return facetsCache;
  }, []);
  return r.data;
}

// --- longest allowed exception (suppress / accept risk), from the risk policy

let policyCache: Promise<RiskPolicy> | null = null;

/** Drops the cached risk policy (call after saving it). */
export function forgetRiskPolicy() {
  policyCache = null;
}

/**
 * Longest suppression or risk acceptance in days. Falls back to the
 * server default (365) while loading or when the policy cannot be read.
 */
export function useExceptionMaxDays(): number {
  const r = useLoad(() => {
    if (!policyCache)
      policyCache = api
        .get<{ policy: RiskPolicy }>("/risk-policy")
        .then((x) => x.policy)
        .catch((e) => {
          policyCache = null;
          throw e;
        });
    return policyCache;
  }, []);
  const n = r.data?.exception_max_days;
  return n && n > 0 ? n : DEFAULT_EXCEPTION_MAX_DAYS;
}

/**
 * Asks before leaving a page with unsaved changes: closing or reloading the
 * tab, and following a link inside the dashboard.
 */
export function useUnsavedChanges(dirty: boolean, message = "You have unsaved changes. Leave without saving?") {
  const navigate = useNavigate();
  useEffect(() => {
    if (!dirty) return;
    const beforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    const click = (e: MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const a = (e.target as Element | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
      if (!a || a.target === "_blank" || a.origin !== window.location.origin) return;
      if (a.pathname === window.location.pathname && a.search === window.location.search) return;
      // Asked in the app's own dialog; the link is followed once confirmed.
      e.preventDefault();
      e.stopPropagation();
      const to = a.pathname + a.search + a.hash;
      void confirmAction({ title: "Leave this page?", message, action: "Leave without saving" }).then((ok) => {
        if (ok) navigate(to);
      });
    };
    window.addEventListener("beforeunload", beforeUnload);
    document.addEventListener("click", click, true);
    return () => {
      window.removeEventListener("beforeunload", beforeUnload);
      document.removeEventListener("click", click, true);
    };
  }, [dirty, message, navigate]);
}
