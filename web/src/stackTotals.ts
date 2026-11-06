/**
 * The Stack tab's total, said so that it does not read as a different count
 * from the asset's own "open issues": the stack adds the findings of every
 * related asset (the host it runs on, its image, its repository...). No
 * imports, so node --test can load it.
 */

const RELATED: Record<string, string> = {
  application: "this application and the assets it runs on",
  host: "this host and the applications on it",
  repository: "this repository and where its code is deployed",
  cluster: "this cluster, its workloads and their images",
  workload: "this workload, its cluster and its images",
  image: "this image and the workloads that run it",
};

/** "375 open findings across this application and the assets it runs on (70 on the application itself)." */
export function stackTotalsText(kind: string, total: number, own: number, truncated = false, members = 2): string {
  const n = `${total.toLocaleString("en-GB")}${truncated ? "+" : ""}`;
  const noun = total === 1 && !truncated ? "open finding" : "open findings";
  const thing = kind in RELATED ? kind : "asset";
  if (members <= 1) return `${n} ${noun} on this ${thing}.`;
  const where = RELATED[kind] ?? "this asset and its related assets";
  const self = `the ${thing}`;
  return `${n} ${noun} across ${where} (${own.toLocaleString("en-GB")}${truncated ? " or more" : ""} on ${self} itself).`;
}
