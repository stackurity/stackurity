import { useState } from "react";
import { Link } from "react-router";
import { uninstallCommands, type Origin } from "../installCommand";
import { Card, Code, CodeBlock, Tabs } from "./ui";

const INSTALL_DOCS = "https://github.com/stackurity/stackurity/blob/main/docs/install.md#what-the-agent-reads-and-sends";

type OS = "linux" | "macos" | "windows";

/**
 * "What the agent does", on Add server before anything is created: what it
 * reads and sends, what it never does, its account, where it connects, how
 * often, and how to remove it. Each statement is backed by the installers
 * (internal/api/install), the agent command (cmd/stackurity/cli.go) and
 * docs/install.md; keep them in step.
 */
export function AgentFacts({ origin = window.location }: { origin?: Origin }) {
  const [os, setOS] = useState<OS>("linux");
  const remove = uninstallCommands(origin);
  return (
    <Card title="What the agent does">
      <div className="grid-2 tight">
        <div>
          <h3>Reads and sends</h3>
          <ul className="banner-list small">
            <li>
              The server&apos;s name and machine ID, its operating system version, packages and installed programs, and on Linux and macOS
              runtimes such as Node.js or Python installed outside the package manager. It sends names, versions and where they were found
              (for rpm packages also the ID of the key that signed each), not file contents.
            </li>
            <li>
              Websites and apps on the server and the libraries they use (on by default), and, if you tick it, the images of
              running Docker containers.
            </li>
            <li>
              Keys and passwords written into those apps&apos; files: the file, line, setting and kind of key, a fingerprint and, for a key, a
              masked preview. Never the key or password itself.
            </li>
          </ul>
          <h3>Changes nothing</h3>
          <ul className="banner-list small">
            <li>It never installs, removes or changes software.</li>
            <li>
              Automatic fixing is a separate paid feature (Pro) for Linux. It needs the agent to run as root, a token an admin binds to that
              server, and a list of allowed packages kept on the server itself. The install command never turns it on.
            </li>
          </ul>
        </div>
        <div>
          <h3>Runs as</h3>
          <ul className="banner-list small">
            <li>
              Its own unprivileged account: <Code>stackurity</Code> on Linux, <Code>_stackurity</Code> on macOS,{" "}
              <Code>NT SERVICE\StackurityAgent</Code> on Windows. Only the install needs root or an administrator.
            </li>
            <li>Checking Docker containers gives it the Docker socket, which is equivalent to root.</li>
          </ul>
          <h3>Connects to</h3>
          <ul className="banner-list small">
            <li>This Stackurity server only, over HTTPS unless you allow plain HTTP. No other address: no telemetry and no update checks.</li>
          </ul>
          <h3>Reports</h3>
          <ul className="banner-list small">
            <li>When it starts and every 6 hours. In between, about once a minute, it asks this server whether someone pressed Check again.</li>
          </ul>
        </div>
      </div>
      <details className="schema-help">
        <summary>Remove the agent</summary>
        <div className="install-command">
          <Tabs<OS>
            label="Operating system to remove the agent from"
            value={os}
            onChange={setOS}
            idPrefix="rm-"
            tabs={[
              { id: "linux", label: "Linux" },
              { id: "windows", label: "Windows" },
              { id: "macos", label: "macOS" },
            ]}
          />
          <div role="tabpanel" id={`rm-panel-${os}`} aria-labelledby={`rm-tab-${os}`} className="tabpanel">
            {os === "windows" && <p className="small">In PowerShell opened with <strong>Run as administrator</strong>:</p>}
            <CodeBlock
              text={remove[os]}
              label={os === "windows" ? "Remove the agent on Windows (PowerShell)" : os === "macos" ? "Remove the agent on macOS" : "Remove the agent on Linux"}
            />
          </div>
        </div>
        <p className="small muted">
          The server stays under <Link to="/assets">Assets</Link> until you delete it there, and its token works until you revoke it under{" "}
          <Link to="/integrations/tokens">API tokens</Link>.
        </p>
      </details>
      <p className="small muted">
        More detail: <Link to="/help/add-server#agent">Help: Add a server</Link> and{" "}
        <a href={INSTALL_DOCS} target="_blank" rel="noopener noreferrer">
          the install guide
        </a>
        . On a Linux server, <Code>stackurity agent --once --output -</Code> prints what the agent collects without sending it.
      </p>
    </Card>
  );
}
