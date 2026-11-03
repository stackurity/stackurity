import { test } from "node:test";
import assert from "node:assert/strict";
import { clearAskState, EMPTY_ASK_STATE, loadAskState, saveAskState } from "./askState.ts";

function memory() {
  const m = new Map<string, string>();
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) };
}

test("the panel comes back after a reload, in the same organisation only", () => {
  const s = memory();
  saveAskState(7, { open: true, minimised: false, conversation: 42, text: "half typ" }, s);
  assert.deepEqual(loadAskState(7, s), { open: true, minimised: false, conversation: 42, text: "half typ" });
  // Another organisation in the same tab never sees it.
  assert.deepEqual(loadAskState(8, s), EMPTY_ASK_STATE);
  clearAskState(s);
  assert.deepEqual(loadAskState(7, s), EMPTY_ASK_STATE);
});

test("bad or missing storage never breaks the panel", () => {
  assert.deepEqual(loadAskState(7, null), EMPTY_ASK_STATE);
  const broken = {
    getItem: () => {
      throw new Error("SecurityError");
    },
    setItem: () => {
      throw new Error("QuotaExceededError");
    },
    removeItem: () => {
      throw new Error("SecurityError");
    },
  };
  assert.deepEqual(loadAskState(7, broken), EMPTY_ASK_STATE);
  saveAskState(7, { ...EMPTY_ASK_STATE, open: true }, broken);
  clearAskState(broken);
  const s = memory();
  s.setItem("stackurity.ask.panel.v1", "{not json");
  assert.deepEqual(loadAskState(7, s), EMPTY_ASK_STATE);
  s.setItem("stackurity.ask.panel.v1", JSON.stringify({ ws: 7, open: "yes", conversation: -3, text: 5 }));
  assert.deepEqual(loadAskState(7, s), EMPTY_ASK_STATE);
  assert.deepEqual(loadAskState(undefined, s), EMPTY_ASK_STATE);
});
