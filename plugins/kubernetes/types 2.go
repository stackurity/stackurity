package main

// The small subset of Kubernetes API objects the plugin reads. Unknown
// fields are ignored, so these work across API versions.

type objectMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	UID             string            `json:"uid"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
	OwnerReferences []ownerRef        `json:"ownerReferences"`
}

type ownerRef struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller"`
}

type containerPort struct {
	ContainerPort int32  `json:"containerPort"`
	HostPort      int32  `json:"hostPort"`
	Protocol      string `json:"protocol"`
}

type container struct {
	Name            string          `json:"name"`
	Image           string          `json:"image"`
	Ports           []containerPort `json:"ports"`
	SecurityContext *struct {
		Privileged *bool `json:"privileged"`
	} `json:"securityContext"`
}

type podSpec struct {
	Containers         []container `json:"containers"`
	InitContainers     []container `json:"initContainers"`
	HostNetwork        bool        `json:"hostNetwork"`
	NodeName           string      `json:"nodeName"`
	ServiceAccountName string      `json:"serviceAccountName"`
	ImagePullSecrets   []struct {
		Name string `json:"name"`
	} `json:"imagePullSecrets"`
}

type podTemplate struct {
	Metadata objectMeta `json:"metadata"`
	Spec     podSpec    `json:"spec"`
}

type containerStatus struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	ImageID string `json:"imageID"`
	State   struct {
		Waiting *struct {
			Reason string `json:"reason"`
		} `json:"waiting"`
	} `json:"state"`
}

type pod struct {
	Metadata objectMeta `json:"metadata"`
	Spec     podSpec    `json:"spec"`
	Status   struct {
		Phase                 string            `json:"phase"`
		ContainerStatuses     []containerStatus `json:"containerStatuses"`
		InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

// controller is a Deployment, StatefulSet, DaemonSet, Job or CronJob,
// reduced to what is common.
type controller struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Replicas    *int32      `json:"replicas"`
		Template    podTemplate `json:"template"`
		Schedule    string      `json:"schedule"`
		Suspend     *bool       `json:"suspend"`
		JobTemplate struct {
			Spec struct {
				Template podTemplate `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
	Status struct {
		ReadyReplicas          int32 `json:"readyReplicas"`
		DesiredNumberScheduled int32 `json:"desiredNumberScheduled"`
		NumberReady            int32 `json:"numberReady"`
		Active                 any   `json:"active"` // int for Jobs, a list for CronJobs
	} `json:"status"`
}

type service struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		Type        string            `json:"type"`
		Selector    map[string]string `json:"selector"`
		ExternalIPs []string          `json:"externalIPs"`
		Ports       []struct {
			Port     int32 `json:"port"`
			NodePort int32 `json:"nodePort"`
		} `json:"ports"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"ingress"`
		} `json:"loadBalancer"`
	} `json:"status"`
}

type ingressBackend struct {
	Service *struct {
		Name string `json:"name"`
	} `json:"service"`
}

type ingress struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		DefaultBackend *ingressBackend `json:"defaultBackend"`
		Rules          []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Backend ingressBackend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
}

type node struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		ProviderID string `json:"providerID"`
	} `json:"spec"`
	Status struct {
		NodeInfo struct {
			KubeletVersion          string `json:"kubeletVersion"`
			OSImage                 string `json:"osImage"`
			KernelVersion           string `json:"kernelVersion"`
			ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
			Architecture            string `json:"architecture"`
			OperatingSystem         string `json:"operatingSystem"`
		} `json:"nodeInfo"`
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
	} `json:"status"`
}

type namespace struct {
	Metadata objectMeta `json:"metadata"`
}

type versionInfo struct {
	GitVersion string `json:"gitVersion"`
	Platform   string `json:"platform"`
}
