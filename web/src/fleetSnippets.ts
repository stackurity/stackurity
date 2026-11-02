/**
 * Ready-made snippets for installing the agent on many servers with one
 * fleet enrollment code (Add server > For many servers). Each one runs the
 * installer served at /install/agent.sh with STACKURITY_ENROLL_CODE; the
 * code is exchanged on each server for that server's own collector token,
 * so no snippet ever holds a long-lived token. The installer skips
 * enrollment where /etc/stackurity/token exists, so a snippet can run twice.
 */

export interface SnippetInput {
  /** The dashboard's origin, e.g. https://stackurity.example.com. */
  origin: string;
  /** The enrollment code (enr_…), shown once. */
  code: string;
  /** The dashboard is on plain HTTP (not localhost): add STACKURITY_ALLOW_HTTP=1. */
  insecure: boolean;
}

export type SnippetKind = "cloud-init" | "ansible" | "terraform" | "ssh";

export interface Snippet {
  kind: SnippetKind;
  title: string;
  /** One line on when to use it. */
  hint: string;
  text: string;
}

/** Enrollment codes are enr_ and lowercase base32, safe in any shell or YAML. */
const CODE = /^enr_[a-z0-9]{8,128}$/;
/** Host names or addresses for the SSH loop: nothing a shell would expand. */
const HOST = /^[A-Za-z0-9_.@:[\]-]{1,255}$/;

function check(i: SnippetInput) {
  if (!CODE.test(i.code)) throw new Error("not an enrollment code");
  if (!/^https?:\/\/[A-Za-z0-9.:[\]-]+$/.test(i.origin)) throw new Error("not a dashboard origin");
}

const SCRIPT = "/run/stackurity-install.sh";

function installer(i: SnippetInput) {
  return `${i.origin}/install/agent.sh`;
}

function envVars(i: SnippetInput, code = i.code) {
  return `STACKURITY_ENROLL_CODE=${code}${i.insecure ? " STACKURITY_ALLOW_HTTP=1" : ""}`;
}

/**
 * The root command, as cloud-init and Terraform run it: download to a file
 * first (a failed download then fails the step, where `curl | sh` would run
 * nothing and succeed), then run it.
 */
function rootCommand(i: SnippetInput, code = i.code) {
  return `curl -fsSL ${installer(i)} -o ${SCRIPT} && ${envVars(i, code)} sh ${SCRIPT}`;
}

export function cloudInit(i: SnippetInput): string {
  check(i);
  return [
    "#cloud-config",
    "# Installs the read-only Stackurity agent on first boot. The enrollment",
    "# code is exchanged for this server's own token; it is not a long-lived",
    "# credential, and it stops working when it expires or is revoked.",
    "runcmd:",
    `  - [ sh, -c, "${rootCommand(i)}" ]`,
    "",
  ].join("\n");
}

export function ansible(i: SnippetInput): string {
  check(i);
  const env = [`        STACKURITY_ENROLL_CODE: "{{ stackurity_enroll_code }}"`];
  if (i.insecure) env.push(`        STACKURITY_ALLOW_HTTP: "1"`);
  return [
    "# stackurity.yml: ansible-playbook -i inventory stackurity.yml",
    "# To keep the code out of the file, delete the vars block and pass",
    "#   -e stackurity_enroll_code=... (or keep it in Ansible Vault).",
    "- name: Install the Stackurity agent",
    "  hosts: all",
    "  become: true",
    "  vars:",
    `    stackurity_enroll_code: "${i.code}"`,
    "  tasks:",
    "    - name: Download the installer",
    "      ansible.builtin.get_url:",
    `        url: ${installer(i)}`,
    `        dest: ${SCRIPT}`,
    '        mode: "0700"',
    "    - name: Install the agent and enroll (skipped where already enrolled)",
    `      ansible.builtin.command: sh ${SCRIPT}`,
    "      args:",
    "        creates: /etc/stackurity/token",
    "      environment:",
    ...env,
    "      no_log: true",
    "",
  ].join("\n");
}

export function terraform(i: SnippetInput): string {
  check(i);
  return [
    "# terraform apply with the code in the environment:",
    `#   TF_VAR_stackurity_enroll_code=${i.code} terraform apply`,
    'variable "stackurity_enroll_code" {',
    "  type      = string",
    "  sensitive = true",
    "}",
    "",
    'resource "digitalocean_droplet" "web" {',
    '  name   = "web-1"',
    '  region = "blr1"',
    '  size   = "s-1vcpu-1gb"',
    '  image  = "ubuntu-24-04-x64"',
    '  tags   = ["stackurity"]',
    "",
    "  # The same user_data works for aws_instance, hcloud_server and others.",
    "  user_data = <<-EOT",
    "    #cloud-config",
    "    runcmd:",
    `      - [ sh, -c, "${rootCommand(i, "${var.stackurity_enroll_code}")}" ]`,
    "  EOT",
    "",
    "  # Changing user_data replaces a droplet that already exists. Add it to",
    "  # new machines, and keep existing ones as they are:",
    "  lifecycle {",
    "    ignore_changes = [user_data]",
    "  }",
    "}",
    "",
  ].join("\n");
}

/** The command for one host over SSH, as a user with sudo. */
export function sshCommand(i: SnippetInput, host: string): string {
  check(i);
  if (!HOST.test(host)) throw new Error("not a host name or address");
  return `ssh ${host} "curl -fsSL ${installer(i)} | sudo ${envVars(i)} sh"`;
}

/** A loop over hosts (names or user@address) reachable with SSH and sudo. */
export function sshLoop(i: SnippetInput, hosts: string[] = ["web-1", "web-2", "db-1"]): string {
  check(i);
  const list = hosts.filter((h) => HOST.test(h));
  if (list.length === 0) throw new Error("no hosts");
  return [
    "# Hosts you can reach with SSH and sudo; edit the list.",
    `hosts="${list.join(" ")}"`,
    "for host in $hosts; do",
    '  echo "== $host"',
    `  ssh "$host" "curl -fsSL ${installer(i)} | sudo ${envVars(i)} sh" || echo "!! failed: $host"`,
    "done",
    "",
  ].join("\n");
}

export function fleetSnippets(i: SnippetInput, hosts?: string[]): Snippet[] {
  return [
    { kind: "cloud-init", title: "cloud-init", hint: "User data for new machines on any cloud (DigitalOcean, AWS, Hetzner, Azure, GCP).", text: cloudInit(i) },
    { kind: "ansible", title: "Ansible", hint: "A play for every host in your inventory.", text: ansible(i) },
    { kind: "terraform", title: "Terraform", hint: "user_data for machines Terraform creates.", text: terraform(i) },
    { kind: "ssh", title: "SSH loop", hint: "For hosts you can already reach with SSH and sudo.", text: sshLoop(i, hosts) },
  ];
}
