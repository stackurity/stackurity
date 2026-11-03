import { test } from "node:test";
import assert from "node:assert/strict";
import { checkAttachments, feedbackForm, feedbackKindLabel, feedbackStatusLabel, formatBytes, MAX_FILES } from "./feedback.ts";

const MB = 1 << 20;
const f = (name: string, type: string, size: number) => ({ name, type, size });

test("images, videos and PDFs within their limits pass", () => {
  const r = checkAttachments([f("shot.png", "image/png", 2 * MB), f("clip.MP4", "video/mp4", 49 * MB), f("report.pdf", "application/pdf", 10 * MB)]);
  assert.deepEqual(r, { fileErrors: [null, null, null], errors: [], ok: true });
  assert.ok(checkAttachments([f("a.jpeg", "image/jpeg", 1), f("b.jpg", "", 1), f("c.webm", "video/webm", 1)]).ok, "an empty media type falls back to the extension");
  assert.ok(checkAttachments([]).ok);
});

test("the type is checked by extension and by media type", () => {
  for (const bad of [f("notes.txt", "text/plain", 10), f("shot.png", "text/html", 10), f("evil.svg", "image/svg+xml", 10), f("movie.mov", "video/quicktime", 10), f("noext", "image/png", 10), f("x.png.exe", "image/png", 10)]) {
    const r = checkAttachments([bad]);
    assert.equal(r.ok, false, bad.name);
    assert.match(r.fileErrors[0] ?? "", /can't be attached/, bad.name);
  }
});

test("each file has its own size limit", () => {
  const img = checkAttachments([f("big.png", "image/png", 10 * MB + 1)]);
  assert.equal(img.ok, false);
  assert.match(img.fileErrors[0] ?? "", /Images may be 10 MB at most/);
  const pdf = checkAttachments([f("big.pdf", "application/pdf", 11 * MB)]);
  assert.match(pdf.fileErrors[0] ?? "", /PDFs may be 10 MB at most/);
  const vid = checkAttachments([f("big.webm", "video/webm", 50 * MB + 1)]);
  assert.match(vid.fileErrors[0] ?? "", /Videos may be 50 MB at most/);
  assert.match(checkAttachments([f("empty.png", "image/png", 0)]).fileErrors[0] ?? "", /empty/);
});

test("at most 3 files and 90 MB together", () => {
  const four = checkAttachments([1, 2, 3, 4].map((i) => f(`s${i}.png`, "image/png", MB)));
  assert.equal(four.ok, false);
  assert.deepEqual(four.fileErrors, [null, null, null, null]);
  assert.deepEqual(four.errors, [`Attach at most ${MAX_FILES} files: remove 1 file.`]);

  const heavy = checkAttachments([f("a.mp4", "video/mp4", 45 * MB), f("b.mp4", "video/mp4", 45 * MB), f("c.png", "image/png", 1 * MB)]);
  assert.equal(heavy.ok, false);
  assert.equal(heavy.errors.length, 1);
  assert.match(heavy.errors[0], /90 MB together at most/);
  assert.ok(checkAttachments([f("a.mp4", "video/mp4", 45 * MB), f("b.mp4", "video/mp4", 45 * MB)]).ok, "exactly 90 MB is allowed");
});

test("sizes read plainly", () => {
  assert.equal(formatBytes(512), "512 bytes");
  assert.equal(formatBytes(2048), "2 KB");
  assert.equal(formatBytes(2.5 * MB), "2.5 MB");
  assert.equal(formatBytes(3 * MB), "3 MB");
  assert.equal(formatBytes(45 * MB), "45 MB");
});

test("the multipart body has the text fields first, then each attachment", async () => {
  const form = feedbackForm({ kind: "issue", message: "Broken", email: "a@b.c", page: "/fixes", viewport: "390x844" }, [new Blob(["x"]), new Blob(["y"])]);
  assert.deepEqual(
    [...form.keys()],
    ["kind", "message", "email", "page", "viewport", "attachment", "attachment"],
  );
  assert.equal(form.get("viewport"), "390x844");
});

test("every status has its own words; released names the version", () => {
  const want: Record<string, string> = {
    received: "Received",
    reviewing: "Under review",
    in_progress: "In progress",
    fixed: "Fixed, waiting for release",
    released: "Released",
    wont_fix: "Won't fix",
    duplicate: "Duplicate",
    unknown: "Unknown",
  };
  for (const [s, label] of Object.entries(want)) assert.equal(feedbackStatusLabel(s, ""), label, s);
  assert.equal(feedbackStatusLabel("released", "0.42.0"), "Released in 0.42.0");
  assert.equal(feedbackStatusLabel("fixed", "0.42.0"), "Fixed, waiting for release", "only released names the version");
  assert.equal(feedbackStatusLabel("something_new"), "Unknown", "a status this version does not know");
  assert.equal(feedbackKindLabel("feature"), "Feature request");
});
