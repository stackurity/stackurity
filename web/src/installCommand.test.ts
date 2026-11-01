import { test } from "node:test";
import assert from "node:assert/strict";
import { linuxCommand, windowsCommand } from "./installCommand.ts";

const https = { origin: "https://stk.example.com", protocol: "https:", hostname: "stk.example.com" };
const plain = { origin: "http://stk.internal:8080", protocol: "http:", hostname: "stk.internal" };
const tunnel = { origin: "http://127.0.0.1:8080", protocol: "http:", hostname: "127.0.0.1" };

test("Linux command", () => {
  assert.deepEqual(linuxCommand("enr_abc", https), {
    command: "curl -fsSL https://stk.example.com/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_abc sh",
    insecure: false,
  });
  assert.equal(linuxCommand("enr_abc", plain).command, "curl -fsSL http://stk.internal:8080/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_abc STACKURITY_ALLOW_HTTP=1 sh");
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
