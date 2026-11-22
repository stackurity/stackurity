import type { AskStatus } from "./ask.ts";

/** A project's notes for Ask Stackurity (GET/PUT /projects/{id}/ask-notes). */
export interface ProjectAskNotes {
  project_id: number;
  notes: string;
  updated_at: string | null;
  max_chars: number;
  can_edit: boolean;
}

/** What the notes mean for Ask right now, for the card's footer. */
export function askNotesStatus(notes: string, status: AskStatus | undefined): string {
  if (notes.trim() === "") return "No notes: Ask Stackurity answers about this project from its data alone.";
  const off = status !== undefined && (status.reason === "ask_disabled" || status.reason === "not_configured" || status.reason === "plan_required");
  if (off) return "Ask Stackurity is off in this organisation. These notes are used once an administrator turns it on.";
  return "Ask Stackurity reads these notes with every question about this project.";
}

/** The notes' length as the server counts it (characters, not UTF-16 units). */
export function askNotesLength(text: string): number {
  return [...text.trim()].length;
}
