import { test } from "node:test";
import assert from "node:assert/strict";
import type { AskStatus } from "./ask.ts";
import { askNotesLength, askNotesStatus } from "./projectAskNotes.ts";

const status = (reason: AskStatus["reason"]) => ({ reason }) as AskStatus;

test("the footer says what the notes do now", () => {
  assert.match(askNotesStatus("", undefined), /No notes/);
  assert.match(askNotesStatus("  ", status("")), /No notes/);
  assert.match(askNotesStatus("Payments API", status("")), /reads these notes/);
  assert.match(askNotesStatus("Payments API", undefined), /reads these notes/);
  assert.match(askNotesStatus("Payments API", status("ask_disabled")), /off in this organisation/);
  assert.match(askNotesStatus("Payments API", status("not_configured")), /off in this organisation/);
});

test("the length counts characters, trimmed", () => {
  assert.equal(askNotesLength("  abc \n"), 3);
  assert.equal(askNotesLength("😀é"), 2);
});
