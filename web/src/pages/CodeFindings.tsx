import { Link } from "react-router";
import { CodeFindingsView } from "../components/CodeFindings";
import { PageHeader } from "../components/ui";

export function CodeFindingsPage() {
  return (
    <>
      <PageHeader
        title="Code findings"
        sub={
          <>
            <strong>What did code scanners find in our own source code?</strong> Findings from code-review security scanners, such as
            deepsec or any tool that writes SARIF, imported for each repository and shown next to its dependency, server and image
            issues. Each one names the file and lines, what is wrong and the suggested fix. When the scanner itself marked one a false
            positive or fixed, it is closed and never alerts. <Link to="/help/code-findings">How to import a report</Link>.
          </>
        }
      />
      <CodeFindingsView />
    </>
  );
}
