import { test } from "node:test";
import assert from "node:assert/strict";
import { assetPlatform } from "./assetPlatform.ts";
import { PLATFORM_LOGOS } from "./platformLogos.ts";

test("hosts show their OS with a short version", () => {
  assert.deepEqual(assetPlatform({ kind: "host", attributes: { os: "ubuntu", os_version: "24.04", os_name: "Ubuntu 24.04.3 LTS" } }), {
    logo: "ubuntu",
    label: "Ubuntu 24.04",
  });
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "rhel", os_version: "9.4.1" } })?.label, "RHEL 9.4");
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "amzn", os_version: "2023" } })?.logo, "aws");
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "windows", os_version: "10.0.26100" } })?.label, "Windows");
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "Windows", os_version: "10.0.26100" } })?.label, "Windows");
});

test("an unknown Linux keeps its own name; nothing reported shows nothing", () => {
  assert.deepEqual(assetPlatform({ kind: "host", attributes: { os: "gentoo", os_name: "Gentoo Linux" } }), { logo: "linux", label: "Gentoo Linux" });
  assert.equal(assetPlatform({ kind: "host", attributes: null }), null);
  assert.equal(assetPlatform({ kind: "application", attributes: { os: "ubuntu" } }), null);
});

test("repositories show where they are hosted", () => {
  assert.equal(assetPlatform({ kind: "repository", attributes: { git_url: "https://github.com/stackurity/stackurity" } })?.label, "GitHub");
  assert.equal(assetPlatform({ kind: "repository", attributes: { git_url: "git@github.com:o/r.git" } })?.label, "GitHub");
  assert.equal(assetPlatform({ kind: "repository", attributes: { git_url: "https://gitlab.example.com/o/r" } })?.label, "GitLab");
  assert.equal(assetPlatform({ kind: "repository", attributes: { git_url: "ssh://git@bitbucket.org/o/r.git" } })?.label, "Bitbucket");
  assert.equal(assetPlatform({ kind: "repository", attributes: { git_url: "https://git.example.com/o/r" } }), null);
  assert.equal(assetPlatform({ kind: "repository", attributes: {} }), null);
});

test("cloud services, images and Kubernetes", () => {
  assert.equal(assetPlatform({ kind: "managed_service", provider: "aws" })?.label, "AWS");
  assert.equal(assetPlatform({ kind: "managed_service", provider: "gcp" })?.logo, "googlecloud");
  assert.equal(assetPlatform({ kind: "image" })?.logo, "docker");
  assert.equal(assetPlatform({ kind: "workload" })?.logo, "kubernetes");
});

test("hosts on a cloud name it next to their OS", () => {
  assert.deepEqual(
    assetPlatform({ kind: "host", attributes: { os: "ubuntu", os_version: "24.04", cloud_provider: "digitalocean", cloud_service: "Droplet" } }),
    { logo: "ubuntu", label: "Ubuntu 24.04", cloud: "DigitalOcean Droplet" },
  );
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "amzn", os_version: "2023", cloud_provider: "aws", cloud_service: "EC2" } })?.cloud, "AWS EC2");
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "debian", cloud_provider: "gcp", cloud_service: "Compute Engine" } })?.cloud, "Google Cloud Compute Engine");
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "debian", cloud_provider: "hetzner", cloud_service: "Cloud server" } })?.cloud, "Hetzner Cloud server");
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "debian", cloud_provider: "linode", cloud_service: "Linode" } })?.cloud, "Akamai (Linode)");
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "gentoo", os_name: "Gentoo", cloud_provider: "vultr", cloud_service: "Instance" } })?.cloud, "Vultr Instance");
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "rocky", cloud_provider: "oracle" } })?.cloud, "Oracle Cloud");
  // Unknown provider, or none: no cloud line.
  assert.equal(assetPlatform({ kind: "host", attributes: { os: "debian", cloud_provider: "ovh", cloud_service: "VPS" } })?.cloud, undefined);
  assert.equal("cloud" in (assetPlatform({ kind: "host", attributes: { os: "debian" } }) ?? {}), false);
});

test("a host with no OS shows its cloud's mark when there is one", () => {
  assert.deepEqual(assetPlatform({ kind: "host", attributes: { cloud_provider: "aws", cloud_service: "EC2" } }), { logo: "aws", label: "AWS EC2" });
  assert.deepEqual(assetPlatform({ kind: "host", attributes: { cloud_provider: "gcp", cloud_service: "Compute Engine" } })?.logo, "googlecloud");
  assert.deepEqual(assetPlatform({ kind: "host", attributes: { cloud_provider: "azure", cloud_service: "Virtual Machine" } })?.logo, "azure");
  // No mark for Hetzner: same as before (the provider field, else nothing).
  assert.equal(assetPlatform({ kind: "host", attributes: { cloud_provider: "hetzner", cloud_service: "Cloud server" } }), null);
  assert.deepEqual(assetPlatform({ kind: "host", provider: "aws", attributes: { cloud_provider: "vultr", cloud_service: "Instance" } }), {
    logo: "aws",
    label: "AWS",
    cloud: "Vultr Instance",
  });
});

test("every mark the mapping can name exists", () => {
  const kinds = ["host", "repository", "managed_service", "image", "cluster", "workload"];
  const oses = ["ubuntu", "debian", "rhel", "centos", "rocky", "almalinux", "fedora", "alpine", "amzn", "sles", "sled", "sle-micro", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "arch", "macos", "windows", "other"];
  const urls = ["https://github.com/a/b", "https://gitlab.com/a/b", "https://bitbucket.org/a/b"];
  for (const kind of kinds)
    for (const os of oses)
      for (const git_url of urls)
        for (const provider of ["aws", "azure", "gcp", "digitalocean"]) {
          for (const cloud_provider of ["", "aws", "azure", "gcp", "digitalocean", "oracle", "hetzner", "linode", "vultr", "alibaba"])
            for (const attributes of [{ os, os_name: os, git_url, cloud_provider }, { cloud_provider }]) {
              const p = assetPlatform({ kind, provider, attributes });
              if (p) assert.ok(PLATFORM_LOGOS[p.logo], `${kind}/${os}/${provider}/${cloud_provider}: ${p.logo}`);
            }
        }
});
