import { test } from "node:test";
import assert from "node:assert/strict";
import { ansible, cloudInit, fleetSnippets, sshCommand, sshLoop, terraform } from "./fleetSnippets.ts";

const code = "enr_abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst";
const input = { origin: "https://stackurity.example.com", code, insecure: false };

test("every snippet carries the enrollment code and no collector token", () => {
  for (const s of fleetSnippets(input)) {
    assert.ok(s.text.includes(code), `${s.kind} lacks the code`);
    assert.ok(!/stk_/.test(s.text), `${s.kind} holds a collector token`);
    assert.ok(!s.text.includes("STACKURITY_TOKEN"), `${s.kind} sets a token`);
    assert.ok(s.text.includes("https://stackurity.example.com/install/agent.sh"), `${s.kind} lacks the installer`);
    assert.ok(!s.text.includes("ALLOW_HTTP"), `${s.kind} allows HTTP over HTTPS`);
  }
});

test("cloud-init is a cloud-config with a runcmd that fails on a failed download", () => {
  const t = cloudInit(input);
  assert.ok(t.startsWith("#cloud-config\n"));
  assert.match(t, /\nruncmd:\n {2}- \[ sh, -c, "curl -fsSL \S+ -o \/run\/stackurity-install\.sh && STACKURITY_ENROLL_CODE=enr_\w+ sh \/run\/stackurity-install\.sh" \]/);
});

test("ansible skips enrolled hosts and keeps the code out of the log", () => {
  const t = ansible(input);
  assert.match(t, /creates: \/etc\/stackurity\/token/);
  assert.match(t, /no_log: true/);
  assert.match(t, /become: true/);
  assert.match(t, /STACKURITY_ENROLL_CODE: "\{\{ stackurity_enroll_code \}\}"/);
});

test("terraform takes the code from a sensitive variable", () => {
  const t = terraform(input);
  assert.match(t, /sensitive = true/);
  assert.match(t, /STACKURITY_ENROLL_CODE=\$\{var\.stackurity_enroll_code\}/);
  assert.match(t, /ignore_changes = \[user_data\]/);
  // The code itself appears only in the comment showing how to pass it.
  assert.equal(t.split(code).length - 1, 1);
});

test("plain HTTP adds STACKURITY_ALLOW_HTTP everywhere", () => {
  for (const s of fleetSnippets({ ...input, origin: "http://10.0.0.5:8080", insecure: true })) {
    assert.ok(s.text.includes("ALLOW_HTTP"), `${s.kind} lacks STACKURITY_ALLOW_HTTP`);
  }
});

test("the SSH loop and per-host commands take only plain host names", () => {
  const t = sshLoop(input, ["root@203.0.113.5", "web-2", "$(reboot)", "a;b"]);
  assert.match(t, /hosts="root@203\.0\.113\.5 web-2"/);
  assert.ok(!t.includes("reboot") && !t.includes("a;b"));
  assert.equal(sshCommand(input, "root@203.0.113.5"), `ssh root@203.0.113.5 "curl -fsSL https://stackurity.example.com/install/agent.sh | sudo STACKURITY_ENROLL_CODE=${code} sh"`);
  assert.throws(() => sshCommand(input, "host; rm -rf /"));
  assert.throws(() => sshLoop(input, ["`id`"]));
});

test("anything but an enrollment code is refused", () => {
  assert.throws(() => cloudInit({ ...input, code: "stk_abcdefghijklmnop" }));
  assert.throws(() => cloudInit({ ...input, code: 'enr_abc" ]\n  - [ sh' }));
  assert.throws(() => cloudInit({ ...input, origin: "https://x.example.com/$(id)" }));
});
