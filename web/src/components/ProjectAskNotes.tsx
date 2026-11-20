import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import type { AskStatus } from "../ask";
import { askNotesLength, askNotesStatus, type ProjectAskNotes } from "../projectAskNotes";
import { useAction, useLoad } from "../hooks";
import { Card, CardFooter, ErrorBox, GoodToKnow, Loading, Notice, SettingRow } from "./ui";

/**
 * The project's notes for Ask Stackurity: a short text its admins write
 * so Ask knows what the project is. Everyone who can see the project can
 * read them; admins of the project change them.
 */
export function ProjectAskNotesCard({ projectId }: { projectId: number }) {
  const res = useLoad(() => api.get<ProjectAskNotes>(`/projects/${projectId}/ask-notes`), [projectId]);
  const status = useLoad(() => api.get<AskStatus>("/ask/status").catch(() => undefined), []);
  const [text, setText] = useState("");
  const [saved, setSaved] = useState(false);
  const act = useAction();
  useEffect(() => {
    if (res.data) setText(res.data.notes);
  }, [res.data]);

  const description =
    "Tell Ask Stackurity what this project is, so its answers fit: what the project runs, which hosts are for testing, what to leave out. Ask reads it as background, never as instructions.";
  if (res.error) {
    return (
      <Card title="Notes for Ask Stackurity" description={description}>
        <ErrorBox error={res.error} title="Could not load the notes" />
      </Card>
    );
  }
  if (!res.data) {
    return (
      <Card title="Notes for Ask Stackurity" description={description}>
        <Loading />
      </Card>
    );
  }
  const n = res.data;
  const changed = text.trim() !== n.notes;
  const length = askNotesLength(text);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaved(false);
    const out = await act.run(() => api.put<ProjectAskNotes>(`/projects/${projectId}/ask-notes`, { notes: text }));
    if (out) {
      setSaved(true);
      res.reload();
    }
  };

  return (
    <Card title="Notes for Ask Stackurity" description={description}>
      <form className="form" onSubmit={submit}>
        {saved && <Notice kind="success">Notes saved. Ask uses them from the next question.</Notice>}
        <ErrorBox error={act.error} title="Could not save the notes" />
        <SettingRow
          title="About this project"
          description={
            n.can_edit
              ? `Plain text, up to ${n.max_chars.toLocaleString()} characters. For example: "Our payments API. web-3 is a staging box. Ignore hosts named lab-*."`
              : "Written by this project's admins. Ask an admin of the project to change them."
          }
        >
          {n.can_edit ? (
            <>
              <label htmlFor={`ask-notes-${projectId}`} className="sr-only">
                Notes for Ask Stackurity
              </label>
              <textarea
                id={`ask-notes-${projectId}`}
                rows={5}
                maxLength={n.max_chars}
                value={text}
                onChange={(e) => {
                  setText(e.target.value);
                  setSaved(false);
                }}
                placeholder="What this project is, which hosts are for testing, what Ask should leave out."
              />
              <p className="hint">
                {length.toLocaleString()} of {n.max_chars.toLocaleString()} characters
              </p>
            </>
          ) : n.notes ? (
            <p style={{ whiteSpace: "pre-wrap" }}>{n.notes}</p>
          ) : (
            <p className="muted">No notes yet.</p>
          )}
        </SettingRow>
        <GoodToKnow>
          Anyone who can see this project can read these notes, and every change is in the audit log with the old and new text. Don&apos;t
          put passwords or keys here: Ask removes anything that looks like one before it reads the notes.
        </GoodToKnow>
        <CardFooter status={askNotesStatus(n.notes, status.data)}>
          {n.can_edit && (
            <>
              <button type="submit" className="btn btn-primary" disabled={act.pending || !changed}>
                Save
              </button>
              <button type="button" className="btn" disabled={act.pending || !changed} onClick={() => setText(n.notes)}>
                Cancel
              </button>
            </>
          )}
        </CardFooter>
      </form>
    </Card>
  );
}
