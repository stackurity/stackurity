/**
 * Requiring single sign-on (Settings, Single sign-on): what the admin is
 * asked about the API tokens and AI assistant connections made before, and
 * what they are told afterwards. Kept free of React for node --test.
 */
import type { ChoiceRequest } from "./confirm";

export type ExistingTokens = "keep" | "revoke";

export interface Revoked {
  api_tokens: number;
  assistant_connections: number;
}

/** The dialog shown when "Require single sign-on for members" is ticked. */
export function requireSSOChoice(isOwner: boolean): ChoiceRequest {
  return {
    title: "Require single sign-on?",
    message:
      "Members will have to sign in with single sign-on to work here. What should happen to the API tokens and AI assistant connections made before?",
    choices: [
      { value: "keep", label: "Keep existing tokens", detail: "API tokens and AI assistant connections keep working." },
      {
        value: "revoke",
        label: "Revoke them",
        detail: isOwner
          ? "Members' API tokens and AI assistant connections stop working. Agents and CI keep theirs. Yours as owner stay."
          : "Members' API tokens and AI assistant connections stop working, yours included. Agents and CI keep theirs. The organisation owner's stay.",
      },
    ],
    action: "Require single sign-on",
  };
}

function count(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** The notice after requiring single sign-on. */
export function requiredNotice(choice: ExistingTokens, revoked?: Revoked | null): string {
  if (choice === "keep") return "Single sign-on is now required. Existing API tokens and AI assistant connections keep working.";
  const r = revoked ?? { api_tokens: 0, assistant_connections: 0 };
  return (
    "Single sign-on is now required. Revoked " +
    count(r.api_tokens, "API token", "API tokens") +
    " and " +
    count(r.assistant_connections, "AI assistant connection", "AI assistant connections") +
    "."
  );
}
