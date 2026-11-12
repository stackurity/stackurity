import { Link } from "react-router";
import { splitPlaces } from "../places";

/**
 * Text that names where things are ("turn it on under Integrations → AI
 * assistants"), with each place a link to its page.
 */
export function PlaceText({ text }: { text: string }) {
  return (
    <>
      {splitPlaces(text).map((p, i) =>
        typeof p === "string" ? (
          p
        ) : (
          <Link key={i} to={p.to}>
            {p.text}
          </Link>
        ),
      )}
    </>
  );
}
