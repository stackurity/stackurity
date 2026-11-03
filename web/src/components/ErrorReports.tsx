import { Component, useContext, type ErrorInfo, type ReactNode } from "react";
import { UNSAFE_LocationContext, UNSAFE_RouteContext } from "react-router";
import { currentRoute, reportException, routePattern } from "../clientErrors";

/**
 * The route pattern of the page this component is on ("/assets/:id"), from
 * react-router's matches, and whether it is inside the signed-in app's
 * routes (sign-in and setup pages are not). Safe outside a router. The
 * contexts are react-router's own: useMatches needs a data router, which
 * the app does not use.
 */
export function useRoutePattern(): { route: string; inApp: boolean } {
  const rc = useContext(UNSAFE_RouteContext);
  const lc = useContext(UNSAFE_LocationContext);
  const matches = rc?.matches ?? [];
  const pathname = lc?.location?.pathname ?? (typeof location !== "undefined" ? location.pathname : "/");
  return { route: routePattern(matches.map((m) => m.route.path), pathname), inApp: matches.length > 0 };
}

/**
 * Catches an error while rendering, reports it (clientErrors.ts) and shows
 * a plain message with a reload button instead of a blank page.
 */
export class ReportingBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error: unknown, _info: ErrorInfo) {
    reportException("render", error, currentRoute());
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="alert alert-error" role="alert" style={{ margin: "2rem" }}>
        <strong>Something went wrong on this page.</strong> Reload the page to try again.{" "}
        <button type="button" className="btn" onClick={() => location.reload()}>
          Reload
        </button>
      </div>
    );
  }
}
