package model

import (
	"fmt"
	"strings"
	"time"
)

// Platform is the infrastructure surface the agent is explaining.
type Platform string

const (
	PlatformLinux      Platform = "linux"
	PlatformKubernetes Platform = "kubernetes"
	PlatformVM         Platform = "vm"
	PlatformBareMetal  Platform = "baremetal"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type IncidentStatus string

const (
	StatusOpen     IncidentStatus = "open"
	StatusResolved IncidentStatus = "resolved"
)

// SignalName is a normalized, pre-aggregated kernel or cgroup observation.
// Agents emit these — never raw trace events — so the analyzer stays scalable.
type SignalName string

const (
	SigRunqP99US        SignalName = "runqlat_p99_us"
	SigRunqNodeP99US    SignalName = "runqlat_node_p99_us"
	SigCPUThrottleRatio SignalName = "cpu_throttle_ratio"
	SigCPUUsageRatio    SignalName = "cpu_usage_ratio"
	SigPSICPUSome       SignalName = "psi_cpu_some"
	SigPSICPUFull       SignalName = "psi_cpu_full"
	SigPSIMemSome       SignalName = "psi_mem_some"
	SigPSIMemFull       SignalName = "psi_mem_full"
	SigPSIIOSome        SignalName = "psi_io_some"
	SigPSIIOFull        SignalName = "psi_io_full"
	SigOOMKills         SignalName = "oom_kills"
	SigMemUsageRatio    SignalName = "mem_usage_ratio"
	SigBiolatP99US      SignalName = "biolat_p99_us"
	SigTCPRetransRate   SignalName = "tcp_retrans_rate"
	SigAcceptDrops      SignalName = "accept_queue_drops"
	SigSoftnetDropped   SignalName = "softnet_dropped"
	SigFDUsageRatio     SignalName = "fd_usage_ratio"
	SigDNSLatencyUS     SignalName = "dns_latency_p99_us"
	SigConntrackUsage   SignalName = "conntrack_usage_ratio"
	SigLoadPerCPU       SignalName = "load1_per_cpu"
)

// Identity is the enriched scope of a signal. eBPF only sees cgroups and pids;
// the agent attaches Kubernetes, VM, or bare-metal context before export.
type Identity struct {
	Platform  Platform `json:"platform"`
	Cluster   string   `json:"cluster,omitempty"`
	Node      string   `json:"node,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Pod       string   `json:"pod,omitempty"`
	Container string   `json:"container,omitempty"`
	VMID      string   `json:"vm_id,omitempty"`
	Hypervisor string  `json:"hypervisor,omitempty"`
	Cgroup    string   `json:"cgroup,omitempty"`
	Host      string   `json:"host,omitempty"`
	Cloud     string   `json:"cloud,omitempty"`
}

// EntityKey is the correlation key. Pod-scoped on Kubernetes, VM-scoped on
// virtual machines, node-scoped otherwise.
func (id Identity) EntityKey() string {
	switch id.Platform {
	case PlatformKubernetes:
		if id.Pod != "" {
			return strings.Join([]string{string(id.Platform), id.Cluster, id.Namespace, id.Pod}, "|")
		}
	case PlatformVM:
		if id.VMID != "" {
			return strings.Join([]string{string(id.Platform), id.VMID}, "|")
		}
	}
	node := id.Node
	if node == "" {
		node = id.Host
	}
	return strings.Join([]string{string(id.Platform), "node", node}, "|")
}

func (id Identity) Subject() string {
	switch id.Platform {
	case PlatformKubernetes:
		if id.Pod != "" {
			ns := id.Namespace
			if ns == "" {
				ns = "default"
			}
			return fmt.Sprintf("pod %s/%s", ns, id.Pod)
		}
	case PlatformVM:
		if id.VMID != "" {
			return "VM " + id.VMID
		}
	case PlatformBareMetal:
		if id.Host != "" {
			return "bare-metal host " + id.Host
		}
	}
	if id.Node != "" {
		return "node " + id.Node
	}
	if id.Host != "" {
		return "host " + id.Host
	}
	return "host"
}

// Signal is one aggregated observation for a single window.
type Signal struct {
	Timestamp time.Time         `json:"timestamp"`
	Identity  Identity          `json:"identity"`
	Name      SignalName        `json:"name"`
	Value     float64           `json:"value"`
	Unit      string            `json:"unit,omitempty"`
	Source    string            `json:"source"`
	WindowSec int               `json:"window_sec"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Evidence is a single fact cited by an explanation.
type Evidence struct {
	Signal    SignalName `json:"signal"`
	Value     float64    `json:"value"`
	Threshold float64    `json:"threshold"`
	Unit      string     `json:"unit,omitempty"`
	Note      string     `json:"note"`
}

// Incident is a sustained fault with a human explanation and the evidence
// that produced it.
type Incident struct {
	ID              string         `json:"id"`
	Status          IncidentStatus `json:"status"`
	Severity        Severity       `json:"severity"`
	Fault           string         `json:"fault"`
	Title           string         `json:"title"`
	Summary         string         `json:"summary"`
	RootCause       string         `json:"root_cause"`
	Recommendations []string       `json:"recommendations"`
	Confidence      float64        `json:"confidence"`
	Identity        Identity       `json:"identity"`
	Evidence        []Evidence     `json:"evidence"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	ResolvedAt      *time.Time     `json:"resolved_at,omitempty"`
	Windows         int            `json:"windows"`
	Source          string         `json:"source"`
}

// Batch is the unit agents export. Pre-aggregation is mandatory: raw eBPF
// events never cross the node boundary.
type Batch struct {
	AgentID   string    `json:"agent_id"`
	Node      string    `json:"node"`
	SentAt    time.Time `json:"sent_at"`
	Signals   []Signal  `json:"signals"`
	Dropped   uint64    `json:"dropped,omitempty"`
	Cluster   string    `json:"cluster,omitempty"`
}

func (b Batch) ShardKey() string {
	if b.Node != "" {
		return b.Node
	}
	return b.AgentID
}
