import { Link } from "react-router";
import { api, type PackList } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { Notice } from "./ui";
import { plural } from "../format";

/**
 * Tells people when their repositories hold files a stack pack could read.
 * Instance admins get a link to install it; everyone else is told whom to ask.
 */
export function PackSuggestions() {
  const { me } = useAuth();
  const res = useLoad(() => api.get<PackList>("/packs"), []);
  const list = res.data?.suggestions ?? [];
  if (list.length === 0) return null;
  return (
    <>
      {list.map((s) => (
        <Notice key={s.id} kind="info">
          {plural(s.files, "file")} in your repositories can&apos;t be read yet. The <strong>{s.name}</strong> stack pack reads them.{" "}
          {me?.user?.instance_admin ? (
            <Link to="/admin/packs">Install it</Link>
          ) : (
            <>Ask your Stackurity administrator to install it.</>
          )}
        </Notice>
      ))}
    </>
  );
}
