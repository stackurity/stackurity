import { Link } from "react-router";
import { EmptyState } from "../components/ui";

export function NotFound() {
  return (
    <EmptyState title="Page not found">
      <p>
        That address does not match any page. <Link to="/">Go to the overview</Link>.
      </p>
    </EmptyState>
  );
}
