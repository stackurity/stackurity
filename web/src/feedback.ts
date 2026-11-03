// Send feedback and My feedback: the parts with no React in them, so they
// can be tested (feedback.test.ts). Limits mirror internal/feedback/attach.go;
// the server checks every file again by its content.

export type FeedbackKind = "issue" | "feature" | "question";

export const FEEDBACK_KINDS: { id: FeedbackKind; label: string; placeholder: string }[] = [
  { id: "issue", label: "Issue", placeholder: "What happened, and what did you expect?" },
  { id: "feature", label: "Feature request", placeholder: "What would make Stackurity better for you?" },
  { id: "question", label: "Question", placeholder: "What would you like to know?" },
];

export function feedbackKindLabel(kind: string): string {
  return FEEDBACK_KINDS.find((k) => k.id === kind)?.label ?? kind;
}

export const FEEDBACK_MAX_CHARS = 5000;

const MB = 1 << 20;
export const MAX_FILES = 3;
export const MAX_IMAGE_BYTES = 10 * MB;
export const MAX_PDF_BYTES = 10 * MB;
export const MAX_VIDEO_BYTES = 50 * MB;
export const MAX_TOTAL_BYTES = 90 * MB;

/** The accept attribute of the file input. */
export const ATTACH_ACCEPT = "image/png,image/jpeg,image/webp,image/gif,video/mp4,video/webm,application/pdf";

type AttachKind = "image" | "video" | "pdf";

/** Extension → what it is and the media types a browser may report for it. */
const EXTENSIONS: Record<string, { kind: AttachKind; types: string[] }> = {
  png: { kind: "image", types: ["image/png"] },
  jpg: { kind: "image", types: ["image/jpeg", "image/jpg", "image/pjpeg"] },
  jpeg: { kind: "image", types: ["image/jpeg", "image/jpg", "image/pjpeg"] },
  webp: { kind: "image", types: ["image/webp"] },
  gif: { kind: "image", types: ["image/gif"] },
  mp4: { kind: "video", types: ["video/mp4"] },
  webm: { kind: "video", types: ["video/webm"] },
  pdf: { kind: "pdf", types: ["application/pdf"] },
};

/** What the checks need from a File (a File satisfies it). */
export interface FileLike {
  name: string;
  size: number;
  type: string;
}

/** "2.4 MB", "830 KB", "120 bytes". */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} ${n === 1 ? "byte" : "bytes"}`;
  if (n < MB) return `${Math.round(n / 1024)} KB`;
  const mb = n / MB;
  return `${mb < 10 ? mb.toFixed(1).replace(/\.0$/, "") : Math.round(mb)} MB`;
}

function maxBytes(kind: AttachKind): number {
  return kind === "video" ? MAX_VIDEO_BYTES : kind === "pdf" ? MAX_PDF_BYTES : MAX_IMAGE_BYTES;
}

export interface AttachmentCheck {
  /** One message per problem with a single file, in list order (null when the file is fine). */
  fileErrors: (string | null)[];
  /** Problems with the set: too many files, too large together. */
  errors: string[];
  ok: boolean;
}

/**
 * Checks chosen files before sending: the type (by extension and the media
 * type the browser reports), each file's size (10 MB for images and PDFs,
 * 50 MB for videos), 90 MB together and at most 3 files.
 */
export function checkAttachments(files: FileLike[]): AttachmentCheck {
  const fileErrors = files.map((f): string | null => {
    const ext = /\.([^./\\]+)$/.exec(f.name)?.[1]?.toLowerCase() ?? "";
    const known = EXTENSIONS[ext];
    const type = f.type.toLowerCase();
    // Some systems report no media type; the extension then decides.
    if (!known || (type !== "" && !known.types.includes(type))) {
      return "This type of file can't be attached. Use PNG, JPEG, WebP or GIF images, MP4 or WebM videos, or PDF.";
    }
    if (f.size === 0) return "This file is empty.";
    const max = maxBytes(known.kind);
    if (f.size > max) {
      const what = known.kind === "video" ? "Videos" : known.kind === "pdf" ? "PDFs" : "Images";
      return `Too large (${formatBytes(f.size)}): ${what} may be ${max / MB} MB at most.`;
    }
    return null;
  });
  const errors: string[] = [];
  if (files.length > MAX_FILES) {
    const extra = files.length - MAX_FILES;
    errors.push(`Attach at most ${MAX_FILES} files: remove ${extra} ${extra === 1 ? "file" : "files"}.`);
  }
  const total = files.reduce((s, f) => s + f.size, 0);
  if (total > MAX_TOTAL_BYTES) {
    errors.push(`The files are ${formatBytes(total)} together; attachments may be ${MAX_TOTAL_BYTES / MB} MB together at most.`);
  }
  return { fileErrors, errors, ok: errors.length === 0 && fileErrors.every((e) => e === null) };
}

export interface FeedbackFields {
  kind: FeedbackKind;
  message: string;
  email: string;
  page: string;
  viewport: string;
}

/**
 * The multipart body: the text fields first (the server reads them before
 * the files), then each file as "attachment".
 */
export function feedbackForm(fields: FeedbackFields, files: Blob[]): FormData {
  const form = new FormData();
  form.append("kind", fields.kind);
  form.append("message", fields.message);
  form.append("email", fields.email);
  form.append("page", fields.page);
  form.append("viewport", fields.viewport);
  for (const f of files) form.append("attachment", f);
  return form;
}

export type FeedbackStatus = "received" | "reviewing" | "in_progress" | "fixed" | "released" | "wont_fix" | "duplicate" | "unknown";

export interface FeedbackItem {
  ref: string;
  kind: string;
  summary: string;
  attachments: number;
  status: FeedbackStatus | string;
  status_note: string;
  fixed_in: string;
  status_at: string | null;
  checked_at: string | null;
  created_at: string;
}

export interface MyFeedback {
  items: FeedbackItem[];
  check_failed?: boolean;
}

const STATUS_LABEL: Record<string, string> = {
  received: "Received",
  reviewing: "Under review",
  in_progress: "In progress",
  fixed: "Fixed, waiting for release",
  released: "Released",
  wont_fix: "Won't fix",
  duplicate: "Duplicate",
  unknown: "Unknown",
};

/** The words shown for a status; a status this version does not know is "Unknown". */
export function feedbackStatusLabel(status: string, fixedIn?: string | null): string {
  const label = STATUS_LABEL[status] ?? "Unknown";
  if (status === "released" && fixedIn?.trim()) return `${label} in ${fixedIn.trim()}`;
  return label;
}

/** Badge tone for a status (components/Badge Tone). */
export function feedbackStatusTone(status: string): "good" | "warn" | "muted" | "info" {
  switch (status) {
    case "received":
    case "reviewing":
      return "info";
    case "in_progress":
      return "warn";
    case "fixed":
    case "released":
      return "good";
    default:
      return "muted";
  }
}
