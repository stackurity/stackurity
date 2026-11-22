import { ConfigFindingsView } from "../components/ConfigFindings";
import { PageHeader } from "../components/ui";

export function ConfigFindingsPage() {
  return (
    <>
      <PageHeader
        title="Risky settings"
        sub={
          <>
            <strong>
              Which settings let someone else run code on my servers?
            </strong>{" "}
            AI coding-agent hooks that download and run code, SSH keys and
            settings that give root a full shell, and GitHub Actions workflows
            that run third-party code by a tag that can move. Each row says why
            it is a risk and the exact change to make in the file. Stackurity
            never stores keys: SSH keys are named by their fingerprint and
            comment.
          </>
        }
      />
      <ConfigFindingsView />
    </>
  );
}
