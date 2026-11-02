// Command kubernetes is a first-party Stackurity plugin that inventories a
// Kubernetes cluster through read-only API calls (get/list only): which
// workloads run which container images, which workloads are reachable from
// outside the cluster, and the control plane, kubelet, container runtime
// and node OS versions for lifecycle.
//
// The collection itself is in package kube, which stackurity
// kubernetes-reporter (the in-cluster push mode) shares.
package main

import (
	"github.com/stackurity/stackurity/pkg/plugin"
	"github.com/stackurity/stackurity/plugins/kubernetes/kube"
)

func main() {
	plugin.Serve(kube.Plugin())
}
