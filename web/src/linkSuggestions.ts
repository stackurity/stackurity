/**
 * The Stack tab's "Suggested links" (components/Stack.tsx): the text of a
 * suggestion that an application is built from a repository. Kept free of
 * React so node --test can load it (linkSuggestions.test.ts).
 */
import type { LinkSuggestion } from "./api";

/** Why the server suggests the pair, strongest first. */
export function suggestionReasons(s: LinkSuggestion): string[] {
  const out: string[] = [];
  if (s.same_package_name) out.push("same package name");
  if (s.dependency_match_percent > 0) out.push(`${s.dependency_match_percent}% of dependencies match`);
  if (s.similar_name) out.push("similar name");
  return out;
}

/** "chat on blog-crm-chat-kb is probably built from commmerce_chat (same package name, 92% of dependencies match)" */
export function suggestionText(s: LinkSuggestion): string {
  const why = suggestionReasons(s);
  return `${s.application.name} is probably built from ${s.repository.name}${why.length ? ` (${why.join(", ")})` : ""}`;
}
