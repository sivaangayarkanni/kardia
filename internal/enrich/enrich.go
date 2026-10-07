package enrich

import (
	"os"
	"strings"

	"github.com/sivaangayarkanni/kardia/internal/model"
)

// Host is what the agent knows about itself before it sees a cgroup.
type Host struct {
	Hostname  string
	Node      string
	Cluster   string
	Platform  model.Platform
	Cloud     string
	VMID      string
	Hypervisor string
}

// Detect reads environment and sysfs. Kubernetes downward API and cloud-init
// override the heuristic. The heuristic never claims Kubernetes without evidence.
func Detect() Host {
	host, _ := os.Hostname()
	h := Host{Hostname: host, Node: host, Platform: model.PlatformLinux}
	if v := os.Getenv("KARDIA_NODE"); v != "" {
		h.Node = v
	}
	if v := os.Getenv("KARDIA_CLUSTER"); v != "" {
		h.Cluster = v
	}
	if v := os.Getenv("KARDIA_PLATFORM"); v != "" {
		h.Platform = model.Platform(v)
	}
	if v := os.Getenv("KARDIA_VM_ID"); v != "" {
		h.VMID = v
		if h.Platform == model.PlatformLinux {
			h.Platform = model.PlatformVM
		}
	}
	if v := os.Getenv("KARDIA_CLOUD"); v != "" {
		h.Cloud = v
	}
	if h.Platform == model.PlatformLinux {
		h.Platform = inferPlatform()
	}
	if h.VMID == "" {
		h.VMID = readFile("/sys/devices/virtual/dmi/id/product_uuid")
	}
	if h.Hypervisor == "" && fileExists("/sys/class/dmi/id/sys_vendor") {
		vendor := strings.ToLower(readFile("/sys/class/dmi/id/sys_vendor"))
		switch {
		case strings.Contains(vendor, "amazon"):
			h.Hypervisor = "nitro"
			h.Cloud = first(h.Cloud, "aws")
			if h.Platform == model.PlatformLinux {
				h.Platform = model.PlatformVM
			}
		case strings.Contains(vendor, "google"):
			h.Hypervisor = "kvm"
			h.Cloud = first(h.Cloud, "gcp")
			if h.Platform == model.PlatformLinux {
				h.Platform = model.PlatformVM
			}
		case strings.Contains(vendor, "microsoft"):
			h.Hypervisor = "hyper-v"
			h.Cloud = first(h.Cloud, "azure")
			if h.Platform == model.PlatformLinux {
				h.Platform = model.PlatformVM
			}
		case strings.Contains(vendor, "qemu") || strings.Contains(vendor, "vmware"):
			h.Hypervisor = vendor
			if h.Platform == model.PlatformLinux {
				h.Platform = model.PlatformVM
			}
		}
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && h.Cluster == "" {
		h.Cluster = first(os.Getenv("KARDIA_CLUSTER"), "in-cluster")
		if h.Platform == model.PlatformLinux || h.Platform == model.PlatformVM {
			// Node can be a VM that is also a Kubernetes node. Prefer kubernetes
			// when the agent is clearly cluster-aware; VM identity stays on VMID.
			h.Platform = model.PlatformKubernetes
		}
	}
	if h.Platform == model.PlatformLinux && isBareMetal() {
		h.Platform = model.PlatformBareMetal
	}
	return h
}

func inferPlatform() model.Platform {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" || os.Getenv("KARDIA_CLUSTER") != "" {
		return model.PlatformKubernetes
	}
	return model.PlatformLinux
}

func isBareMetal() bool {
	vendor := strings.ToLower(readFile("/sys/class/dmi/id/sys_vendor"))
	if vendor == "" {
		return false
	}
	virtual := []string{"qemu", "vmware", "amazon", "google", "microsoft", "xen", "innotek", "bochs"}
	for _, v := range virtual {
		if strings.Contains(vendor, v) {
			return false
		}
	}
	return true
}

// PodIdentity builds a Kubernetes identity from a cgroup path.
// kubepods-burstable-podUID.slice / crio / containerd paths are all accepted.
func PodIdentity(host Host, cgroupPath, namespace, pod, container string) model.Identity {
	id := model.Identity{
		Platform:  host.Platform,
		Cluster:   host.Cluster,
		Node:      host.Node,
		Host:      host.Hostname,
		Cloud:     host.Cloud,
		VMID:      host.VMID,
		Hypervisor: host.Hypervisor,
		Cgroup:    cgroupPath,
		Namespace: namespace,
		Pod:       pod,
		Container: container,
	}
	if pod != "" && id.Platform != model.PlatformKubernetes {
		id.Platform = model.PlatformKubernetes
	}
	return id
}

func NodeIdentity(host Host) model.Identity {
	return model.Identity{
		Platform:   host.Platform,
		Cluster:    host.Cluster,
		Node:       host.Node,
		Host:       host.Hostname,
		Cloud:      host.Cloud,
		VMID:       host.VMID,
		Hypervisor: host.Hypervisor,
	}
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func first(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
