import { test } from "node:test";
import assert from "node:assert/strict";
import { detailsComplete, detailsRule } from "./billingDetails.ts";

const b = { vat_countries: ["DE", "FR", "GR"] };
const empty = { legal_name: "", address: "", state: "", tax_id: "" };

test("the EU needs a VAT number, India a state, others nothing", () => {
  assert.equal(detailsRule("DE", b), "vat");
  assert.equal(detailsRule("IN", b), "state");
  assert.equal(detailsRule("GB", b), "optional");
  assert.equal(detailsRule("CH", b), "optional");
});

test("complete details per rule", () => {
  assert.equal(detailsComplete("DE", { ...empty, legal_name: "Muster GmbH", address: "Berlin" }, b), false);
  assert.equal(detailsComplete("DE", { ...empty, legal_name: "Muster GmbH", address: "Berlin", tax_id: "DE123456789" }, b), true);
  assert.equal(detailsComplete("IN", empty, b), false);
  assert.equal(detailsComplete("IN", { ...empty, state: "29" }, b), true);
  assert.equal(detailsComplete("IN", { ...empty, tax_id: "27AAPFU0939F1ZV" }, b), true);
  assert.equal(detailsComplete("US", empty, b), true);
});
