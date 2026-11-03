import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { linuxCommand, macCommand, uninstallCommands, windowsCommand } from "./installCommand.ts";

const https = { origin: "https://stk.example.com", protocol: "https:", hostname: "stk.example.com" };
const plain = { origin: "http://stk.internal:8080", protocol: "http:", hostname: "stk.internal" };
const tunnel = { origin: "http://127.0.0.1:8080", protocol: "http:", hostname: "127.0.0.1" };

test("Linux command", () => {
  assert.deepEqual(linuxCommand("enr_abc", https), {
    command: "curl -fsSL https://stk.example.com/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_abc sh",
    insecure: false,
  });
  assert.equal(linuxCommand("enr_abc", plain).command, "curl -fsSL http://stk.internal:8080/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_abc STACKURITY_ALLOW_HTTP=1 sh");
  assert.equal(linuxCommand("enr_abc", https, true).command, "curl -fsSL https://stk.example.com/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_abc STACKURITY_DOCKER=1 sh");
});

test("Windows command: TLS 1.2, the code in a single-quoted string, irm piped to iex", () => {
  assert.deepEqual(windowsCommand("enr_abc", https), {
    command:
      "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; " +
      "$env:STACKURITY_ENROLL_CODE = 'enr_abc'; irm https://stk.example.com/install/agent.ps1 | iex",
    insecure: false,
  });
  const p = windowsCommand("enr_abc", plain);
  assert.equal(p.insecure, true);
  assert.match(p.command, /\$env:STACKURITY_ALLOW_HTTP = '1'; irm http:\/\/stk\.internal:8080\/install\/agent\.ps1 \| iex$/);
  // A local port (an SSH tunnel) needs no override, as for Linux.
  assert.equal(windowsCommand("enr_abc", tunnel).insecure, false);
  assert.doesNotMatch(windowsCommand("enr_abc", tunnel).command, /ALLOW_HTTP/);
});

test("macOS command: the LaunchDaemon installer, no Docker option", () => {
  assert.deepEqual(macCommand("enr_abc", https), {
    command: "curl -fsSL https://stk.example.com/install/agent-macos.sh | sudo STACKURITY_ENROLL_CODE=enr_abc sh",
    insecure: false,
  });
  assert.equal(macCommand("enr_abc", plain).insecure, true);
});

test("Uninstall commands: the installers' STACKURITY_UNINSTALL on macOS and Windows, by hand on Linux", () => {
  const u = uninstallCommands(https);
  assert.equal(u.macos, "curl -fsSL https://stk.example.com/install/agent-macos.sh | sudo STACKURITY_UNINSTALL=1 sh");
  assert.equal(
    u.windows,
    "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; " +
      "$env:STACKURITY_UNINSTALL = '1'; irm https://stk.example.com/install/agent.ps1 | iex",
  );
  // Everything agent.sh installs: the unit, the binary, the token's directory and the user.
  for (const part of ["disable --now stackurity-agent", "/etc/systemd/system/stackurity-agent.service", "/usr/local/bin/stackurity", "rm -rf /etc/stackurity", "userdel stackurity"]) {
    assert.ok(u.linux.includes(part), part);
  }
  // Removing needs no plain-HTTP override: the scripts uninstall before checking the URL.
  assert.doesNotMatch(uninstallCommands(plain).macos + uninstallCommands(plain).windows, /ALLOW_HTTP/);
});

test("The Linux uninstall removes what agent.sh installs", () => {
  const script = readFileSync(new URL("../../internal/api/install/agent.sh", import.meta.url), "utf8");
  const linux = uninstallCommands(https).linux;
  for (const want of ["CONF=/etc/stackurity", "BIN=/usr/local/bin/stackurity", "UNIT=/etc/systemd/system/stackurity-agent.service", "useradd --system"]) {
    assert.ok(script.includes(want), `agent.sh no longer has ${want}: update uninstallCommands`);
  }
  const unit = /systemctl enable --quiet (\S+)/.exec(script)?.[1];
  assert.equal(unit, "stackurity-agent");
  assert.ok(linux.includes(`disable --now ${unit}`));
});
