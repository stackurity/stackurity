import type { PlatformLogo } from "./platformLogos.ts";

/** What an asset runs on or lives in, as people name it: "Ubuntu 24.04", "GitHub", "AWS". */
export interface AssetPlatform {
  logo: PlatformLogo;
  label: string;
}

interface PlatformInput {
  kind: string;
  provider?: string;
  attributes?: Record<string, string> | null;
}

/** os-release ID (and the darwin/windows collectors' "macos"/"windows") → mark and name. */
const OS: Record<string, AssetPlatform> = {
  ubuntu: { logo: "ubuntu", label: "Ubuntu" },
  debian: { logo: "debian", label: "Debian" },
  rhel: { logo: "redhat", label: "RHEL" },
  centos: { logo: "centos", label: "CentOS" },
  rocky: { logo: "rockylinux", label: "Rocky Linux" },
  almalinux: { logo: "almalinux", label: "AlmaLinux" },
  fedora: { logo: "fedora", label: "Fedora" },
  alpine: { logo: "alpinelinux", label: "Alpine" },
  amzn: { logo: "aws", label: "Amazon Linux" },
  sles: { logo: "suse", label: "SUSE" },
  sled: { logo: "suse", label: "SUSE" },
  "sle-micro": { logo: "suse", label: "SUSE Micro" },
  opensuse: { logo: "opensuse", label: "openSUSE" },
  "opensuse-leap": { logo: "opensuse", label: "openSUSE Leap" },
  "opensuse-tumbleweed": { logo: "opensuse", label: "openSUSE" },
  arch: { logo: "archlinux", label: "Arch Linux" },
  macos: { logo: "apple", label: "macOS" },
  windows: { logo: "windows", label: "Windows" },
};

const CLOUD: Record<string, AssetPlatform> = {
  aws: { logo: "aws", label: "AWS" },
  azure: { logo: "azure", label: "Azure" },
  gcp: { logo: "googlecloud", label: "Google Cloud" },
  digitalocean: { logo: "digitalocean", label: "DigitalOcean" },
};

/** "24.04.3" → "24.04"; "12" stays "12". Full detail is on the asset page. */
function shortVersion(v: string): string {
  return v.split(".").slice(0, 2).join(".");
}

function gitHost(url: string): AssetPlatform | null {
  // https://github.com/o/r, git@github.com:o/r.git, ssh://git@gitlab.example.com/o/r
  const host = (/^[a-z+]+:\/\/(?:[^@/]+@)?([^/:]+)/i.exec(url) ?? /^[^@/]+@([^:/]+):/.exec(url))?.[1]?.toLowerCase() ?? "";
  if (host === "github.com" || host.endsWith(".github.com") || host.endsWith(".ghe.com")) return { logo: "github", label: "GitHub" };
  if (host.includes("gitlab")) return { logo: "gitlab", label: "GitLab" };
  if (host === "bitbucket.org" || host.includes("bitbucket")) return { logo: "bitbucket", label: "Bitbucket" };
  return null;
}

/**
 * The platform to show next to an asset's kind, from what its collector
 * reported. Null when nothing says (the plain kind is shown then).
 */
export function assetPlatform(a: PlatformInput): AssetPlatform | null {
  const at = a.attributes ?? {};
  switch (a.kind) {
    case "host": {
      const os = OS[(at.os ?? "").toLowerCase()];
      if (os) {
        const v = at.os_version && a.attributes?.os !== "windows" ? shortVersion(at.os_version) : "";
        return { ...os, label: v ? `${os.label} ${v}` : os.label };
      }
      if (at.os || at.os_name) return { logo: "linux", label: at.os_name || at.os };
      return CLOUD[(a.provider ?? "").toLowerCase()] ?? null;
    }
    case "repository":
      return at.git_url ? gitHost(at.git_url) : null;
    case "managed_service":
      return CLOUD[(a.provider ?? "").toLowerCase()] ?? null;
    case "image":
      return { logo: "docker", label: "Container image" };
    case "cluster":
    case "workload":
      return { logo: "kubernetes", label: "Kubernetes" };
    default:
      return null;
  }
}
