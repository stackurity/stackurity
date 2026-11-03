// The one-line agent installers shown under Add server and in the first-run
// flow. internal/mcp/write.go builds the same commands for AI assistants.

const LOCAL_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

/** Where the dashboard is open: window.location, or a test's stand-in. */
export interface Origin {
  origin: string;
  protocol: string;
  hostname: string;
}

/** The installers refuse plain HTTP to anything but a local port unless told otherwise. */
function isInsecure(loc: Origin): boolean {
  return loc.protocol === "http:" && !LOCAL_HOSTS.includes(loc.hostname);
}

/**
 * The one-line installer for a new Linux host. With docker, it also gives
 * the agent access to the Docker socket (STACKURITY_DOCKER=1).
 */
export function linuxCommand(code: string, loc: Origin, docker = false): { command: string; insecure: boolean } {
  const insecure = isInsecure(loc);
  const env = `STACKURITY_ENROLL_CODE=${code}${insecure ? " STACKURITY_ALLOW_HTTP=1" : ""}${docker ? " STACKURITY_DOCKER=1" : ""}`;
  return { command: `curl -fsSL ${loc.origin}/install/agent.sh | sudo ${env} sh`, insecure };
}

/** The one-line installer for a Mac (agent-macos.sh, a LaunchDaemon). */
export function macCommand(code: string, loc: Origin): { command: string; insecure: boolean } {
  const insecure = isInsecure(loc);
  const env = `STACKURITY_ENROLL_CODE=${code}${insecure ? " STACKURITY_ALLOW_HTTP=1" : ""}`;
  return { command: `curl -fsSL ${loc.origin}/install/agent-macos.sh | sudo ${env} sh`, insecure };
}

/**
 * The one-line installer for a new Windows host, for PowerShell run as
 * administrator. The first statement turns on TLS 1.2, which Windows
 * PowerShell 5.1 on Windows Server 2016 does not offer by default;
 * `irm | iex` runs the script as text, so the execution policy does not
 * apply.
 */
export function windowsCommand(code: string, loc: Origin): { command: string; insecure: boolean } {
  const insecure = isInsecure(loc);
  const tls = "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; ";
  const env = `$env:STACKURITY_ENROLL_CODE = '${code}'; ${insecure ? "$env:STACKURITY_ALLOW_HTTP = '1'; " : ""}`;
  return { command: `${tls}${env}irm ${loc.origin}/install/agent.ps1 | iex`, insecure };
}
