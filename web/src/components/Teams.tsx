import { useState, type KeyboardEvent } from "react";
import { Link } from "react-router";
import { api, type Team } from "../api";
import { useAuth } from "../auth";
import { useAction } from "../hooks";
import { ProNotice } from "./ProNotice";
import { ErrorBox } from "./ui";

/**
 * Under a team dropdown with no teams to choose: where teams are made.
 * Admins get a link to Settings, Teams; everyone else is told to ask one.
 */
export function NoTeamsHint({ what = "choose one here" }: { what?: string }) {
  const { can } = useAuth();
  return (
    <p className="hint">
      No teams yet.{" "}
      {can("admin") ? (
        <>
          Create one under <Link to="/settings/teams">Settings, Teams</Link> to {what}.
        </>
      ) : (
        <>Ask an administrator to create one under Settings, Teams.</>
      )}
    </p>
  );
}

/**
 * Creates a team by name where one is needed (admins). It is not a form of
 * its own, so it can sit inside another form. Community includes one team:
 * past that, it explains the plan instead.
 */
export function NewTeamInline({ id, teams, onCreated, onCancel }: { id: string; teams: number; onCreated: (t: Team) => void; onCancel?: () => void }) {
  const { has } = useAuth();
  const [name, setName] = useState("");
  const act = useAction();
  if (!has("teams") && teams >= 1) return <ProNotice feature="teams">Community includes one team. </ProNotice>;
  const create = async () => {
    if (!name.trim()) return;
    const t = await act.run(() => api.post<Team>("/teams", { name: name.trim() }));
    if (t) {
      setName("");
      onCreated(t);
    }
  };
  const enter = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      void create();
    }
  };
  return (
    <div className="new-team-inline">
      <ErrorBox error={act.error} title="Could not create the team" />
      <label htmlFor={id}>New team name</label>
      <div className="new-team-row">
        <input id={id} maxLength={100} value={name} onChange={(e) => setName(e.target.value)} onKeyDown={enter} placeholder="e.g. Web team" />
        <button type="button" className="btn" onClick={() => void create()} disabled={act.pending || !name.trim()}>
          Create team
        </button>
        {onCancel && (
          <button type="button" className="btn btn-link" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
      <p className="hint">Add people to it later under Settings, Teams.</p>
    </div>
  );
}
