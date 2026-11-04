import { contextWords, passwordRules, passwordStrength, RULE_LABELS, RULES, STRENGTH_LABELS } from "../passwordStrength";

/**
 * Under a field that sets a password: the rules, each ticked as it is met,
 * and a strength meter. The strength is said in words (and announced), not
 * only by the bar's colour. id goes in the field's aria-describedby.
 * context is what the person typed about themselves (email, name,
 * organisation): a password made of it is weak.
 */
export function PasswordChecklist({ id, password, context = [] }: { id: string; password: string; context?: (string | undefined)[] }) {
  const rules = passwordRules(password);
  const { strength } = passwordStrength(password, contextWords(...context));
  const empty = password === "";
  return (
    <div className="pw-strength" id={id}>
      <ul className="pw-rules" aria-label="Password rules">
        {RULES.map((k) => (
          <li key={k} className={rules[k] ? "pw-rule pw-rule-met" : "pw-rule"}>
            <span className="pw-rule-mark" aria-hidden="true">
              {rules[k] ? "✓" : "○"}
            </span>
            {RULE_LABELS[k]}
            <span className="sr-only">{rules[k] ? " (done)" : " (missing)"}</span>
          </li>
        ))}
      </ul>
      <div className="pw-meter" data-strength={empty ? "none" : strength} aria-hidden="true">
        <span className="pw-meter-bar" />
      </div>
      <p className="pw-meter-label" aria-live="polite">
        {empty ? "" : (
          <>
            Strength: <strong>{STRENGTH_LABELS[strength]}</strong>
          </>
        )}
      </p>
    </div>
  );
}

/** Under a confirm field: whether the two passwords match, once something is typed. */
export function PasswordMatch({ password, confirm }: { password: string; confirm: string }) {
  const match = password === confirm;
  return (
    <p className={confirm === "" ? "hint" : match ? "hint pw-match" : "hint hint-error"} aria-live="polite">
      {confirm === "" ? "" : match ? "✓ Passwords match" : "Passwords don't match"}
    </p>
  );
}
