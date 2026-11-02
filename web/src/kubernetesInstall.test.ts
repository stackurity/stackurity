// Run with `npm test` (node --test, TypeScript types stripped).
import { test } from "node:test";
import assert from "node:assert/strict";
import { clusterCommands, parseNamespaces, validClusterName } from "./kubernetesInstall.ts";

test("cluster-wide install commands", () => {
  const c = clusterCommands({ origin: "https://stk.example.com", code: "enr_abc", cluster: "prod-eu", namespaces: [], version: "0.14.0" });
  assert.equal(
    c.helm,
    "helm install stackurity-reporter oci://ghcr.io/stackurity/charts/stackurity-reporter --version 0.14.0 \\\n" +
      "  --namespace stackurity --create-namespace \\\n" +
      "  --set server=https://stk.example.com --set clusterName=prod-eu --set enrollCode=enr_abc",
  );
  assert.equal(
    c.kubectl,
    "kubectl apply -f 'https://stk.example.com/install/kubernetes.yaml?cluster=prod-eu' && \\\n" +
      "  kubectl -n stackurity create secret generic stackurity-reporter --from-literal=enroll-code=enr_abc",
  );
  assert.equal(c.insecure, false);
});

test("the code is never in the manifest's address", () => {
  const c = clusterCommands({ origin: "https://stk.example.com", code: "enr_secret", cluster: "x", namespaces: ["shop"] });
  const url = /kubectl apply -f '([^']+)'/.exec(c.kubectl)![1];
  assert.ok(!url.includes("enr_"), url);
});

test("namespace-scoped install", () => {
  const c = clusterCommands({ origin: "https://stk.example.com", code: "enr_abc", cluster: "lab", namespaces: ["shop", "blog"], version: "dev" });
  assert.ok(c.helm.includes("--set rbac.clusterWide=false --set 'namespaces={shop,blog}'"));
  assert.ok(!c.helm.includes("--version"), "a development build pins no chart version");
  assert.ok(c.kubectl.includes("/install/kubernetes.yaml?cluster=lab&namespaces=shop,blog'"));
});

test("plain HTTP is allowed explicitly and flagged", () => {
  const c = clusterCommands({ origin: "http://stk.internal:8080", code: "enr_abc", cluster: "lab", namespaces: [] });
  assert.ok(c.helm.includes("--set allowHTTP=true"));
  assert.equal(c.insecure, true);
  assert.equal(clusterCommands({ origin: "http://localhost:8080", code: "e", cluster: "lab", namespaces: [] }).insecure, false);
});

test("names are checked before they reach a shell command", () => {
  assert.ok(validClusterName("prod-eu.1"));
  for (const bad of ["", "a b", "x;rm", "$(id)", "a'b"]) assert.ok(!validClusterName(bad), bad);
  assert.deepEqual(parseNamespaces("shop, blog\nshop"), ["shop", "blog"]);
  assert.equal(parseNamespaces("Shop"), null);
  assert.equal(parseNamespaces("a;b"), null);
  assert.deepEqual(parseNamespaces(""), []);
});
