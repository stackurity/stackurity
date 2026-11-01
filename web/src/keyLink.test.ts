// Run with `npm test` (node --test, TypeScript types stripped).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseKeyReturn, resumePath, safeRedirect } from "./keyLink.ts";

const key = "eyJ2IjoxLCJpZCI6ImNrXzEyMyJ9" + "A".repeat(20) + "." + "c2lnbmF0dXJl" + "B".repeat(70);
const state = "cks_" + "a".repeat(52);

test("a key and its state from the fragment", () => {
  assert.deepEqual(parseKeyReturn(`#key=${key}&state=${state}`), { kind: "key", key, state });
  // Percent-encoded as URLSearchParams writes it, and in either order.
  assert.deepEqual(parseKeyReturn(`#state=${encodeURIComponent(state)}&key=${encodeURIComponent(key)}`), { kind: "key", key, state });
});

test("no fragment: nothing to do", () => {
  assert.deepEqual(parseKeyReturn(""), { kind: "none" });
  assert.deepEqual(parseKeyReturn("#"), { kind: "none" });
});

test("the Cloud says no key was issued", () => {
  assert.equal(parseKeyReturn(`#error=access_denied&state=${state}`).kind, "error");
});

test("anything else is refused before it reaches the server", () => {
  for (const h of [
    `#key=${key}`, // no state
    `#state=${state}`, // no key
    `#key=${key}&state=cks_UPPER${"a".repeat(40)}`,
    `#key=${key}&state=${state}&state=${state}`, // twice
    `#key=${key}&key=${key}&state=${state}`,
    `#key=not-a-key&state=${state}`,
    `#key=${key}%0Aevil&state=${state}`,
    `#key=<script>&state=${state}`,
    `#key=${key}&state=xyz_${"a".repeat(52)}`,
  ]) {
    assert.equal(parseKeyReturn(h).kind, "error", h);
  }
});

test("resuming after sign-up goes only to the Cloud's own key page, for an hour", () => {
  const now = 1_800_000_000_000;
  const save = (path: string, at = now) => JSON.stringify({ path, at });
  assert.equal(resumePath(save("/community-key/new?return=https%3A%2F%2Fx.example&state=s"), now), "/community-key/new?return=https%3A%2F%2Fx.example&state=s");
  assert.equal(resumePath(save("/community-key/new?x=1", now - 2 * 3600 * 1000), now), null); // too old
  for (const p of ["https://evil.example/community-key/new?x", "//evil.example/community-key/new?x", "/community-key/new", "/settings?x", "/community-key/new?\\evil"]) {
    assert.equal(resumePath(save(p), now), null, p);
  }
  assert.equal(resumePath("not json", now), null);
  assert.equal(resumePath(null, now), null);
});

test("the Cloud's redirect is followed only to the host the person confirmed", () => {
  const r = `https://stackurity.example.com/setup/community-key#key=${key}&state=${state}`;
  assert.equal(safeRedirect(r, "stackurity.example.com"), r);
  assert.equal(safeRedirect("http://10.0.0.5:8080/setup/community-key#key=k", "10.0.0.5:8080"), "http://10.0.0.5:8080/setup/community-key#key=k");
  assert.equal(safeRedirect(r, "other.example.com"), null);
  assert.equal(safeRedirect("javascript:alert(1)//setup/community-key", "stackurity.example.com"), null);
  assert.equal(safeRedirect("https://a:b@stackurity.example.com/setup/community-key#k", "stackurity.example.com"), null);
  assert.equal(safeRedirect("https://stackurity.example.com/elsewhere#k", "stackurity.example.com"), null);
});
