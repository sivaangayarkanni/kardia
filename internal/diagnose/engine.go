package diagnose

import (
	"fmt"
	"strings"

	"github.com/sivaangayarkanni/kardia/internal/model"
)

// Snapshot is the latest window of signals for one entity.
type Snapshot map[model.SignalName]float64

func (s Snapshot) get(name model.SignalName) (float64, bool) {
	v, ok := s[name]
	return v, ok
}

// Result is a single fault hypothesis produced from one window.
type Result struct {
	Fault           string
	Severity        model.Severity
	Confidence      float64
	Title           string
	Summary         string
	RootCause       string
	Recommendations []string
	Evidence        []model.Evidence
	// Sustain is how many consecutive windows are required before opening.
	// OOM is immediate (1); noisy ratios need 2.
	Sustain int
}

// Engine evaluates production fault rules against aggregated kernel signals.
// Rules are confirmation-based: a single spike is not an incident unless the
// fault class is discrete (OOM kill).
type Engine struct {
	cfg Config
}

type Config struct {
	ThrottleRatio    float64
	RunqNodeP99US    float64
	RunqPodP99US     float64
	PSIFull          float64
	PSISome          float64
	BiolatP99US      float64
	TCPRetransRate   float64
	AcceptDrops      float64
	SoftnetDropped   float64
	FDUsage          float64
	MemUsage         float64
	DNSLatencyUS     float64
	ConntrackUsage   float64
	LoadPerCPU       float64
}

func DefaultConfig() Config {
	return Config{
		ThrottleRatio:  0.15,
		RunqNodeP99US:  10000, // 10ms: node is saturated
		RunqPodP99US:   2000,
		PSIFull:        5,
		PSISome:        20,
		BiolatP99US:    20000, // 20ms
		TCPRetransRate: 0.02,
		AcceptDrops:    1,
		SoftnetDropped: 50,
		FDUsage:        0.85,
		MemUsage:       0.92,
		DNSLatencyUS:   50000, // 50ms
		ConntrackUsage: 0.80,
		LoadPerCPU:     1.5,
	}
}

func New(cfg Config) *Engine { return &Engine{cfg: cfg} }

// Evaluate returns every fault that matches this window, highest confidence first.
func (e *Engine) Evaluate(id model.Identity, snap Snapshot) []Result {
	var out []Result
	rules := []func(model.Identity, Snapshot) *Result{
		e.ruleOOM,
		e.ruleCFSThrottle,
		e.ruleCPUSaturation,
		e.ruleMemoryPressure,
		e.ruleDiskSaturation,
		e.ruleTCPLoss,
		e.ruleAcceptOverflow,
		e.ruleSoftirq,
		e.ruleFDExhaustion,
		e.ruleDNS,
		e.ruleConntrack,
	}
	for _, rule := range rules {
		if r := rule(id, snap); r != nil {
			out = append(out, *r)
		}
	}
	return out
}

func ev(name model.SignalName, value, threshold float64, unit, note string) model.Evidence {
	return model.Evidence{Signal: name, Value: value, Threshold: threshold, Unit: unit, Note: note}
}

func (e *Engine) ruleOOM(id model.Identity, snap Snapshot) *Result {
	kills, ok := snap.get(model.SigOOMKills)
	if !ok || kills < 1 {
		return nil
	}
	mem, _ := snap.get(model.SigMemUsageRatio)
	subject := id.Subject()
	cause := fmt.Sprintf("%s crossed its memory limit and the kernel OOM killer ran. %.0f process(es) were killed in this window.", subject, kills)
	if id.Platform == model.PlatformKubernetes {
		cause = fmt.Sprintf("The container cgroup memory.max was exceeded on %s. The kernel invoked the OOM killer (%.0f kill(s)). This is a limit event, not necessarily node-wide memory exhaustion.", subject, kills)
	}
	recs := []string{
		"Inspect dmesg / the oom_kill eBPF event for the killed comm and rss.",
		"Compare working set against the cgroup memory limit before raising it.",
		"Look for a leak (rss slope) versus a legitimate traffic spike.",
	}
	if id.Platform == model.PlatformKubernetes {
		recs = append(recs, "Raise the pod memory limit only after confirming the node has reclaimable headroom; otherwise the kill moves to the node OOM killer.")
	}
	return &Result{
		Fault: "oom_kill", Severity: model.SevCritical, Confidence: 0.96, Sustain: 1,
		Title:     "OOM kill on " + subject,
		Summary:   fmt.Sprintf("%s was OOM-killed (%.0f in the last window). Memory usage ratio at observation was %.0f%%.", subject, kills, mem*100),
		RootCause: cause,
		Recommendations: recs,
		Evidence: []model.Evidence{
			ev(model.SigOOMKills, kills, 1, "kills", "oom_kill tracepoint fired"),
			ev(model.SigMemUsageRatio, mem, e.cfg.MemUsage, "ratio", "cgroup or host memory usage"),
		},
	}
}

func (e *Engine) ruleCFSThrottle(id model.Identity, snap Snapshot) *Result {
	throttle, ok := snap.get(model.SigCPUThrottleRatio)
	if !ok || throttle < e.cfg.ThrottleRatio {
		return nil
	}
	nodeRunq, _ := snap.get(model.SigRunqNodeP99US)
	podRunq, _ := snap.get(model.SigRunqP99US)
	psi, _ := snap.get(model.SigPSICPUSome)
	// If the node itself is saturated, CPU saturation is the better explanation.
	if nodeRunq >= e.cfg.RunqNodeP99US {
		return nil
	}
	subject := id.Subject()
	sev := model.SevHigh
	if throttle >= 0.40 {
		sev = model.SevCritical
	}
	scope := "cgroup CPU controller"
	if id.Platform == model.PlatformKubernetes {
		scope = "Kubernetes CPU limit (cgroup cpu.max)"
	}
	return &Result{
		Fault: "cfs_throttle", Severity: sev, Confidence: clamp(0.7+throttle, 0.99), Sustain: 2,
		Title:   "CPU limit throttling " + subject,
		Summary: fmt.Sprintf("%s is being denied CPU by the %s. %.0f%% of demanded CPU time was throttled. Node run-queue p99 is %.0fµs, so this is a limit, not host saturation.", subject, scope, throttle*100, nodeRunq),
		RootCause: fmt.Sprintf("%s is enforcing a CPU ceiling below demand. Tasks are runnable inside the cgroup (pod run-queue p99 %.0fµs, cpu PSI some %.1f%%) but the controller is not granting the quota. Application latency here is scheduling delay caused by the limit, not by lock contention or node overload.", subject, podRunq, psi),
		Recommendations: []string{
			"Raise the CPU limit, or remove it and keep a request for scheduling.",
			"HPA on CPU usage will under-scale while throttled, because usage is capped at the limit. Scale on a latency or RPS metric instead.",
			"On cgroup v2, cpu.max.burst can absorb short spikes without raising the steady limit.",
			"Confirm the throttle is this container and not a parent Burstable QoS cgroup.",
		},
		Evidence: []model.Evidence{
			ev(model.SigCPUThrottleRatio, throttle, e.cfg.ThrottleRatio, "ratio", "throttled_usec / (throttled_usec + usage_usec)"),
			ev(model.SigRunqNodeP99US, nodeRunq, e.cfg.RunqNodeP99US, "us", "node run queue is healthy, ruling out noisy-neighbor saturation"),
			ev(model.SigRunqP99US, podRunq, e.cfg.RunqPodP99US, "us", "cgroup-local run queue"),
			ev(model.SigPSICPUSome, psi, e.cfg.PSISome, "percent", "tasks stalled on CPU inside the cgroup"),
		},
	}
}

func (e *Engine) ruleCPUSaturation(id model.Identity, snap Snapshot) *Result {
	nodeRunq, ok := snap.get(model.SigRunqNodeP99US)
	if !ok || nodeRunq < e.cfg.RunqNodeP99US {
		return nil
	}
	throttle, _ := snap.get(model.SigCPUThrottleRatio)
	if throttle >= e.cfg.ThrottleRatio {
		return nil
	}
	load, _ := snap.get(model.SigLoadPerCPU)
	psi, _ := snap.get(model.SigPSICPUFull)
	subject := id.Subject()
	where := "The node CPU run queue is saturated."
	if id.Platform == model.PlatformVM {
		where = "The guest run queue is saturated. Steal time from the hypervisor can look identical — compare with the host if steal is non-zero."
	}
	if id.Platform == model.PlatformBareMetal {
		where = "Bare-metal run queue is saturated. There is no hypervisor steal; this is physical CPU demand."
	}
	return &Result{
		Fault: "cpu_saturation", Severity: model.SevHigh, Confidence: 0.84, Sustain: 2,
		Title:   "CPU saturation on " + subject,
		Summary: fmt.Sprintf("Scheduler run-queue p99 is %.1fms on %s (threshold %.1fms). Load per CPU is %.2f. CPU PSI full is %.1f%%.", nodeRunq/1000, subject, e.cfg.RunqNodeP99US/1000, load, psi),
		RootCause: where + " Tasks are waiting to be scheduled. This is not CFS throttling (throttle ratio is below threshold). Latency-sensitive threads will stall in runnable state.",
		Recommendations: []string{
			"Identify the top cgroups by cpu.stat usage_usec and move or cap the noisy neighbor.",
			"On Kubernetes, check for Burstable/BestEffort pods packing the node. Cordon before the latency SLO burns.",
			"On a VM, check steal time. If steal is high the fix is on the hypervisor, not in the guest.",
			"Scale the node pool or pin IRQ / softirq load off the application CPUs.",
		},
		Evidence: []model.Evidence{
			ev(model.SigRunqNodeP99US, nodeRunq, e.cfg.RunqNodeP99US, "us", "sched_wakeup to sched_switch delay, node scope"),
			ev(model.SigLoadPerCPU, load, e.cfg.LoadPerCPU, "load", "load1 divided by online CPUs"),
			ev(model.SigPSICPUFull, psi, e.cfg.PSIFull, "percent", "all tasks stalled on CPU"),
			ev(model.SigCPUThrottleRatio, throttle, e.cfg.ThrottleRatio, "ratio", "throttle ruled out"),
		},
	}
}

func (e *Engine) ruleMemoryPressure(id model.Identity, snap Snapshot) *Result {
	full, ok := snap.get(model.SigPSIMemFull)
	some, _ := snap.get(model.SigPSIMemSome)
	if !ok || (full < e.cfg.PSIFull && some < e.cfg.PSISome*2) {
		return nil
	}
	if kills, _ := snap.get(model.SigOOMKills); kills >= 1 {
		return nil
	}
	usage, _ := snap.get(model.SigMemUsageRatio)
	subject := id.Subject()
	return &Result{
		Fault: "memory_pressure", Severity: model.SevHigh, Confidence: 0.8, Sustain: 2,
		Title:   "Memory reclaim stalls on " + subject,
		Summary: fmt.Sprintf("Memory PSI full is %.1f%% and some is %.1f%% on %s. Usage ratio is %.0f%%. No OOM kill in this window — the kernel is stalling allocators in reclaim instead.", full, some, subject, usage*100),
		RootCause: "Anonymous or page-cache reclaim cannot keep up with allocation. Tasks block in direct reclaim (PSI full) even though the OOM killer has not run. On container hosts this often means the node is overcommitted while individual pods are still under their limits.",
		Recommendations: []string{
			"Check /proc/vmstat for pgscan and working-set refaults, and whether swap is active.",
			"Reduce page cache pressure (logging, image pulls) or move workloads off the node.",
			"On Kubernetes, memory requests are not limits: a node can enter reclaim while every pod is 'within limit'.",
			"If this is a VM, ballooning or host reclaim can present as guest PSI with no guest OOM.",
		},
		Evidence: []model.Evidence{
			ev(model.SigPSIMemFull, full, e.cfg.PSIFull, "percent", "tasks stalled in reclaim"),
			ev(model.SigPSIMemSome, some, e.cfg.PSISome, "percent", "partial memory stalls"),
			ev(model.SigMemUsageRatio, usage, e.cfg.MemUsage, "ratio", "usage against visible RAM or cgroup limit"),
		},
	}
}

func (e *Engine) ruleDiskSaturation(id model.Identity, snap Snapshot) *Result {
	bio, ok := snap.get(model.SigBiolatP99US)
	ioFull, _ := snap.get(model.SigPSIIOFull)
	ioSome, _ := snap.get(model.SigPSIIOSome)
	if !ok || bio < e.cfg.BiolatP99US || (ioFull < e.cfg.PSIFull && ioSome < e.cfg.PSISome) {
		return nil
	}
	subject := id.Subject()
	diskNote := "Block-layer completion latency is high and tasks are stalled on IO."
	if id.Platform == model.PlatformVM {
		diskNote = "Guest block latency is high. On virtio this is often host storage or a throttled volume, not a guest filesystem bug."
	}
	if id.Platform == model.PlatformKubernetes {
		diskNote = "Pod IO is waiting on the node block layer. emptyDir, container image overlay, and PVC all share this device unless the volume is remote."
	}
	return &Result{
		Fault: "disk_saturation", Severity: model.SevHigh, Confidence: 0.82, Sustain: 2,
		Title:   "Disk saturation on " + subject,
		Summary: fmt.Sprintf("Block I/O p99 is %.1fms and IO PSI full is %.1f%% on %s.", bio/1000, ioFull, subject),
		RootCause: diskNote + " Application threads in write or fsync will stall. This is not CPU saturation unless run-queue latency is also high.",
		Recommendations: []string{
			"Find the cgroup with the highest io.stat bytes and throttle it, or move the volume.",
			"Check for fsync-heavy logging and for image garbage collection on containerd.",
			"On a cloud VM, compare volume IOPS credits. Burst balance exhaustion looks like a sudden p99 cliff.",
			"Separate write-ahead logs onto a volume that is not shared with overlayfs.",
		},
		Evidence: []model.Evidence{
			ev(model.SigBiolatP99US, bio, e.cfg.BiolatP99US, "us", "block_rq_complete latency p99 from eBPF"),
			ev(model.SigPSIIOFull, ioFull, e.cfg.PSIFull, "percent", "tasks stalled on IO"),
			ev(model.SigPSIIOSome, ioSome, e.cfg.PSISome, "percent", "partial IO stalls"),
		},
	}
}

func (e *Engine) ruleTCPLoss(id model.Identity, snap Snapshot) *Result {
	rate, ok := snap.get(model.SigTCPRetransRate)
	if !ok || rate < e.cfg.TCPRetransRate {
		return nil
	}
	subject := id.Subject()
	return &Result{
		Fault: "tcp_loss", Severity: model.SevHigh, Confidence: 0.78, Sustain: 2,
		Title:   "TCP retransmission loss on " + subject,
		Summary: fmt.Sprintf("TCP retransmission rate is %.2f%% on %s (threshold %.2f%%).", rate*100, subject, e.cfg.TCPRetransRate*100),
		RootCause: "Segments are being retransmitted faster than the loss budget. Typical causes are a congested path, a full NIC ring, conntrack drops, or a blackholed route. The eBPF tcp:tcp_retransmit_skb counter is host-wide unless a cgroup filter was attached.",
		Recommendations: []string{
			"Split retransmits by destination from the tcp_retransmit_skb events before blaming the application.",
			"Check softnet drops and NIC pause frames; local drops masquerade as remote loss.",
			"On Kubernetes, compare pod-to-pod (CNI overlay MTU) against pod-to-service (kube-proxy / conntrack).",
			"If only one peer is affected, the fault is on that path, not the node.",
		},
		Evidence: []model.Evidence{
			ev(model.SigTCPRetransRate, rate, e.cfg.TCPRetransRate, "ratio", "retransmits / segments out over the window"),
		},
	}
}

func (e *Engine) ruleAcceptOverflow(id model.Identity, snap Snapshot) *Result {
	drops, ok := snap.get(model.SigAcceptDrops)
	if !ok || drops < e.cfg.AcceptDrops {
		return nil
	}
	subject := id.Subject()
	return &Result{
		Fault: "accept_queue_overflow", Severity: model.SevCritical, Confidence: 0.9, Sustain: 1,
		Title:   "Listen backlog overflow on " + subject,
		Summary: fmt.Sprintf("%.0f SYNs were dropped because the accept queue was full on %s.", drops, subject),
		RootCause: "The kernel listen backlog (somaxconn / the socket backlog passed to listen) is overflowing. Clients complete the handshake or get a timeout, but the accept queue never drains. The process is not calling accept fast enough, or a worker pool is wedged.",
		Recommendations: []string{
			"Increase the application backlog and somaxconn only after confirming workers are unblocked.",
			"A wedged event loop (blocked on disk or a lock) produces this with healthy CPU. Check biolat and run queue together.",
			"On Kubernetes this often surfaces as readiness-probe failures and 502s from the Service, not as CPU throttling.",
		},
		Evidence: []model.Evidence{
			ev(model.SigAcceptDrops, drops, e.cfg.AcceptDrops, "drops", "ListenOverflows / ListenDrops from TCP SNMP or eBPF"),
		},
	}
}

func (e *Engine) ruleSoftirq(id model.Identity, snap Snapshot) *Result {
	dropped, ok := snap.get(model.SigSoftnetDropped)
	if !ok || dropped < e.cfg.SoftnetDropped {
		return nil
	}
	subject := id.Subject()
	return &Result{
		Fault: "softirq_saturation", Severity: model.SevHigh, Confidence: 0.8, Sustain: 2,
		Title:   "NET_RX softirq drops on " + subject,
		Summary: fmt.Sprintf("%.0f packets were dropped in softnet_stat on %s this window. The kernel is not polling the NIC fast enough.", dropped, subject),
		RootCause: "napi / NET_RX softirq is falling behind. Packets are dropped before they reach the socket. This is a host networking fault: IRQ affinity, a saturated RX CPU, or a CPU-limited VM. Application threads never see these packets.",
		Recommendations: []string{
			"Spread NIC IRQs (irqbalance or explicit affinity) off the hot CPU.",
			"On a VM, check the virtio queue count against vCPUs. A single queue on a 16-vCPU guest drops here first.",
			"If this coincides with CFS throttle on a sidecar that shares the CPU, the throttle is starving softirq.",
		},
		Evidence: []model.Evidence{
			ev(model.SigSoftnetDropped, dropped, e.cfg.SoftnetDropped, "packets", "softnet_stat dropped column, summed"),
		},
	}
}

func (e *Engine) ruleFDExhaustion(id model.Identity, snap Snapshot) *Result {
	usage, ok := snap.get(model.SigFDUsageRatio)
	if !ok || usage < e.cfg.FDUsage {
		return nil
	}
	subject := id.Subject()
	return &Result{
		Fault: "fd_exhaustion", Severity: model.SevCritical, Confidence: 0.88, Sustain: 2,
		Title:   "File descriptor exhaustion on " + subject,
		Summary: fmt.Sprintf("File descriptor usage is %.0f%% of the kernel file-max on %s.", usage*100, subject),
		RootCause: "The host is near fs.file-max (or a cgroup pid/fd ceiling). New sockets and files will fail with EMFILE/ENFILE even though CPU and memory look fine. Connection churn without close is the usual source.",
		Recommendations: []string{
			"Find the pid with the largest fd table (walk /proc/*/fd) before raising file-max.",
			"On Kubernetes the container rlimit nofile is independent of the node file-max. Check both.",
			"TIME_WAIT accumulation from short connections can exhaust ports before fds. Check the ephemeral port range.",
		},
		Evidence: []model.Evidence{
			ev(model.SigFDUsageRatio, usage, e.cfg.FDUsage, "ratio", "file-nr allocated / file-max"),
		},
	}
}

func (e *Engine) ruleDNS(id model.Identity, snap Snapshot) *Result {
	lat, ok := snap.get(model.SigDNSLatencyUS)
	if !ok || lat < e.cfg.DNSLatencyUS {
		return nil
	}
	subject := id.Subject()
	return &Result{
		Fault: "dns_latency", Severity: model.SevWarning, Confidence: 0.7, Sustain: 2,
		Title:   "DNS latency on " + subject,
		Summary: fmt.Sprintf("DNS p99 is %.0fms on %s (threshold %.0fms).", lat/1000, subject, e.cfg.DNSLatencyUS/1000),
		RootCause: "UDP exchanges to port 53 are slow. On Kubernetes this is usually CoreDNS throttled or a conntrack full table, not application code. eBPF timestamps the send and the matching recv on cgroup skb.",
		Recommendations: []string{
			"Check CoreDNS CPU throttle and upstream timeout before tuning application resolvers.",
			"ndots and search-path expansion multiply queries per lookup. A slow DNS plus a wide search path dominates tail latency.",
			"If conntrack usage is also high, DNS UDP replies are being dropped, which looks like latency.",
		},
		Evidence: []model.Evidence{
			ev(model.SigDNSLatencyUS, lat, e.cfg.DNSLatencyUS, "us", "cgroup skb DNS RTT p99"),
		},
	}
}

func (e *Engine) ruleConntrack(id model.Identity, snap Snapshot) *Result {
	usage, ok := snap.get(model.SigConntrackUsage)
	if !ok || usage < e.cfg.ConntrackUsage {
		return nil
	}
	subject := id.Subject()
	return &Result{
		Fault: "conntrack_pressure", Severity: model.SevHigh, Confidence: 0.86, Sustain: 2,
		Title:   "Conntrack table pressure on " + subject,
		Summary: fmt.Sprintf("nf_conntrack usage is %.0f%% of the table on %s.", usage*100, subject),
		RootCause: "The netfilter connection tracker is near nf_conntrack_max. New flows are dropped (nf_conntrack: table full) even when the NIC and the accept queue are healthy. kube-proxy and Docker both depend on this table.",
		Recommendations: []string{
			"Raise nf_conntrack_max only after confirming the hash buckets can hold it, and shorten established TCP timeouts if churn is the cause.",
			"NAT-heavy Services and hairpin traffic multiply entries. Prefer endpoint routing where the CNI allows it.",
			"Drops here are invisible to TCP retransmit metrics until the client retries.",
		},
		Evidence: []model.Evidence{
			ev(model.SigConntrackUsage, usage, e.cfg.ConntrackUsage, "ratio", "nf_conntrack_count / nf_conntrack_max"),
		},
	}
}

func clamp(v, max float64) float64 {
	if v > max {
		return max
	}
	return v
}

// FormatEvidence renders evidence as plain lines for logs and CLI output.
func FormatEvidence(evs []model.Evidence) string {
	var b strings.Builder
	for _, e := range evs {
		fmt.Fprintf(&b, "  - %s = %.4g (threshold %.4g %s) %s\n", e.Signal, e.Value, e.Threshold, e.Unit, e.Note)
	}
	return b.String()
}
