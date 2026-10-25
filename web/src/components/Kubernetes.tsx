import type { ReactNode } from "react";
import { Link } from "react-router";
import type { Asset, Relation } from "../api";
import { ExposureBadge } from "./Badge";
import { Card, KeyValues } from "./ui";

/** Workload attributes shown in the Kubernetes card rather than as raw attributes. */
export const WORKLOAD_ATTRS = [
  "cluster",
  "namespace",
  "workload_kind",
  "workload_name",
  "replicas",
  "ready",
  "pods",
  "exposure",
  "exposed_via",
  "services",
  "images",
  "schedule",
];

function muted(text: string) {
  return <span className="muted">{text}</span>;
}

function assetLinks(items: { id: number; name: string }[], empty: string): ReactNode {
  if (items.length === 0) return muted(empty);
  return (
    <ul className="plain-list">
      {items.map((i) => (
        <li key={i.id}>
          <Link className="mono break" to={`/assets/${i.id}`}>
            {i.name}
          </Link>
        </li>
      ))}
    </ul>
  );
}

/**
 * What the Kubernetes plugin knows about a workload (its cluster, exposure
 * and the images it runs), a cluster (versions and workload counts) or an
 * image (the workloads running it). Nothing is shown for other assets.
 */
export function KubernetesCard({ asset, relations }: { asset: Asset; relations: Relation[] }) {
  const at = asset.attributes ?? {};
  const out = relations.filter((r) => r.from_asset === asset.id);
  const into = relations.filter((r) => r.to_asset === asset.id);

  if (asset.kind === "workload") {
    const cluster = out.filter((r) => r.kind === "runs_on").map((r) => ({ id: r.to_asset, name: r.to_name }));
    const images = out.filter((r) => r.kind === "deployed_as").map((r) => ({ id: r.to_asset, name: r.to_name }));
    const replicas = at.replicas ? `${at.ready ?? "?"} of ${at.replicas} ready` : at.pods ? `${at.pods} pods` : "";
    return (
      <Card title="Kubernetes workload">
        <KeyValues
          entries={[
            ["workload", `${at.workload_kind ?? "?"} ${at.workload_name ?? ""}`],
            ["namespace", at.namespace || muted("unknown")],
            ["cluster", cluster.length ? assetLinks(cluster, "") : at.cluster || muted("unknown")],
            ...(replicas ? ([["replicas", replicas]] as [string, ReactNode][]) : []),
            ...(at.schedule ? ([["schedule", <span className="mono">{at.schedule}</span>]] as [string, ReactNode][]) : []),
            [
              "exposure",
              <>
                <ExposureBadge asset={asset} /> {at.exposed_via && <span className="break">{at.exposed_via}</span>}
                {!at.exposed_via && at.exposure === "internal" && muted("no LoadBalancer, NodePort, Ingress or host port")}
              </>,
            ],
            ["services", at.services || muted("none")],
            [
              "images",
              assetLinks(images, at.images ? at.images : "none recorded"),
            ],
          ]}
        />
        {images.length === 0 && at.images && (
          <p className="hint">The images are not linked yet; they are linked on the next collection.</p>
        )}
      </Card>
    );
  }

  if (asset.kind === "cluster") {
    const prefix = `${asset.name}/`;
    return (
      <Card title="Kubernetes cluster">
        <KeyValues
          entries={[
            ["version", at.kubernetes_version || muted("unknown")],
            ...(at.distribution ? ([["distribution", at.distribution]] as [string, ReactNode][]) : []),
            ["nodes", at.nodes ? `${at.nodes_ready ?? "?"} of ${at.nodes} ready` : muted("unknown (nodes could not be read)")],
            [
              "workloads",
              <>
                <Link to={`/assets?kind=workload&q=${encodeURIComponent(prefix)}`}>{at.workloads ?? "0"}</Link>
                {at.exposed_workloads && at.exposed_workloads !== "0" && (
                  <>
                    {", "}
                    <Link to={`/assets?kind=workload&exposed=true&q=${encodeURIComponent(prefix)}`}>{at.exposed_workloads} exposed</Link>
                  </>
                )}
              </>,
            ],
            ["images", at.images ?? "0"],
          ]}
        />
        <p className="hint">Kubelet, container runtime and node OS versions are on the Inventory tab, with the nodes that run each.</p>
      </Card>
    );
  }

  if (asset.kind === "image") {
    const workloads = into.filter((r) => r.kind === "deployed_as").map((r) => ({ id: r.from_asset, name: r.from_name }));
    if (workloads.length === 0) return null;
    return (
      <Card title="Running in Kubernetes">
        <KeyValues
          entries={[
            ["workloads", assetLinks(workloads, "none")],
            ["exposure", <ExposureBadge asset={asset} />],
            ...(at.tags ? ([["tags in manifests", <span className="mono break">{at.tags}</span>]] as [string, ReactNode][]) : []),
          ]}
        />
      </Card>
    );
  }
  return null;
}
