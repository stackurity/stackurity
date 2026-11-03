import { Link, type To } from "react-router";
import type { NoFixAdvice } from "../api";
import { plural } from "../format";
import { CodeBlock } from "./ui";

/**
 * "How to fix" for issues with no fixed version: per package, whether it is
 * fixed under another name, unmaintained, or has no fix yet, grouped by
 * kind; once at the top, that the packages come with the application and
 * how to see what pulls each one in; then the decisions the fix page
 * already offers.
 */
export function NoFixAdviceView({ advice, accept, snooze }: { advice: NoFixAdvice; accept: To; snooze: To }) {
  const b = advice.bundled;
  const commands = b?.commands ?? [];
  return (
    <div className="nofix">
      {b && (
        <div className="nofix-bundled">
          <p>{b.text}</p>
          {commands.length > 0 && (
            <>
              <p className="small muted">To see which of {b.app}&apos;s dependencies pulls each one in:</p>
              {commands.map((c) => (
                <CodeBlock key={c} label="Command" text={c} />
              ))}
            </>
          )}
        </div>
      )}
      {advice.sections.map((s) => (
        <section key={s.kind} className="nofix-section" aria-label={s.title}>
          <h3 className="nofix-title">
            {s.title} ({plural(s.issues, "issue")})
          </h3>
          <ul className="nofix-list">
            {s.items.map((it) => (
              <li key={`${it.component}@${it.version}`}>
                <span className="mono">
                  <strong>{it.component}</strong> {it.version}
                </span>{" "}
                <span className="small muted">{it.issues.join(", ")}</span>
                <br />
                {it.text}
                {it.workaround && (
                  <blockquote className="nofix-workaround">
                    <span className="small muted">Workaround, as {it.workaround_source || "the advisory"} gives it:</span>
                    <span className="nofix-quote">{it.workaround}</span>
                  </blockquote>
                )}
              </li>
            ))}
          </ul>
        </section>
      ))}
      <p className="small">
        <strong>Until then:</strong> <Link to={accept}>mitigate it with a note</Link>, <Link to={accept}>accept the risk until a date</Link> or{" "}
        <Link to={accept}>ignore it with a reason</Link>; or <Link to={snooze}>snooze it until a fix is published</Link>.
      </p>
    </div>
  );
}
