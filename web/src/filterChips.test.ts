import { test } from "node:test";
import assert from "node:assert/strict";
import { activeFilters, withoutFilter, withoutFilters, type FilterDef } from "./filterChips.ts";

const DEFS: FilterDef[] = [
  { key: "status", label: "Status", defaultValue: "open" },
  { key: "kind", label: "Kind", format: (v) => (v === "end_of_life" ? "End of life" : v) },
  { key: "team_id", label: "Owner team", format: (v) => ({ "4": "Payments" })[v] ?? "" },
  { key: "sos", label: "SOS only", flag: true },
];

test("one chip per filter on, in the page's order, with readable values", () => {
  const p = new URLSearchParams("sos=true&kind=end_of_life&team_id=4&offset=50&tab=x");
  assert.deepEqual(activeFilters(p, DEFS), [
    { key: "kind", text: "Kind: End of life" },
    { key: "team_id", text: "Owner team: Payments" },
    { key: "sos", text: "SOS only" },
  ]);
});

test("empty values, default values and flags that are off make no chip", () => {
  assert.deepEqual(activeFilters(new URLSearchParams("status=open&kind=&sos=false"), DEFS), []);
  assert.deepEqual(activeFilters(new URLSearchParams(""), DEFS), []);
  assert.deepEqual(activeFilters(new URLSearchParams("status=resolved"), DEFS), [{ key: "status", text: "Status: resolved" }]);
});

test("a format that knows nothing about the value falls back to the raw value", () => {
  assert.deepEqual(activeFilters(new URLSearchParams("team_id=9"), DEFS), [{ key: "team_id", text: "Owner team: 9" }]);
});

test("removing a filter keeps the others and goes back to the first page", () => {
  const p = new URLSearchParams("kind=host&sos=true&offset=100&tab=rules");
  assert.equal(withoutFilter(p, "kind").toString(), "sos=true&tab=rules");
  assert.equal(p.toString(), "kind=host&sos=true&offset=100&tab=rules", "the original is not changed");
});

test("Clear all removes only the page's filters", () => {
  const p = new URLSearchParams("kind=host&sos=true&status=all&offset=100&tab=rules");
  assert.equal(withoutFilters(p, DEFS).toString(), "tab=rules");
});
