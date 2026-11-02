import { Link } from "react-router";
import { PERMISSION_NOTES, permissionTable } from "../roles";
import { Inline } from "../help/render";

/**
 * "What can each do?": the permissions table, from the same source as the
 * help article "Users, teams and roles" (roles.ts).
 */
export function PermissionsDisclosure() {
  const [head, ...rows] = permissionTable();
  return (
    <details className="permissions-help">
      <summary>What can each permission do?</summary>
      <div className="table-wrap">
        <table className="table permissions-table">
          <caption className="sr-only">What each permission can do</caption>
          <thead>
            <tr>
              {head.map((h, i) => (
                <th key={h} scope="col" className={i ? "num" : undefined}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r[0]}>
                <td className="perm-what">{r[0]}</td>
                {r.slice(1).map((c, i) => (
                  <td key={head[i + 1]} className={`num perm-${c === "No" ? "no" : c === "Yes" ? "yes" : "all"}`}>
                    {c}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <ul className="small">
        {PERMISSION_NOTES.map((n) => (
          <li key={n}>
            <Inline text={n} />
          </li>
        ))}
      </ul>
      <p className="small">
        <Link to="/help/users-teams-roles">More in the help: Users, teams and roles</Link>
      </p>
    </details>
  );
}
