package ebpf

import (
	"fmt"
	"os"
	"runtime"
)

// Capability describes whether this process can load the CO-RE programs in bpf/.
// The programs themselves are compiled out-of-band (make bpf) into bpf/out.
// Loading uses the standard bpf syscall; this package does not vendor a loader
// so the diagnosis binary stays portable. On a production node the agent
// process in deploy/k8s is granted CAP_BPF and CAP_PERFMON and runs Load().
type Capability struct {
	Kernel     string
	HasBTF     bool
	HasCapBPF  bool
	ObjectDir  string
	Objects    []string
	Reason     string
}

func Probe(objectDir string) Capability {
	c := Capability{Kernel: runtime.GOOS + "/" + runtime.GOARCH, ObjectDir: objectDir}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		c.HasBTF = true
	}
	if c.KernelHasBPF() {
		c.HasCapBPF = true
	}
	entries, _ := os.ReadDir(objectDir)
	for _, e := range entries {
		if !e.IsDir() {
			c.Objects = append(c.Objects, e.Name())
		}
	}
	switch {
	case !c.HasBTF:
		c.Reason = "kernel BTF missing at /sys/kernel/btf/vmlinux; CO-RE load disabled, proc collector remains active"
	case len(c.Objects) == 0:
		c.Reason = "no compiled BPF objects in " + objectDir + "; run `make bpf` on a kernel with BTF headers"
	default:
		c.Reason = "BTF present and objects found; attach via the node DaemonSet (CAP_BPF, CAP_PERFMON)"
	}
	return c
}

func (c Capability) KernelHasBPF() bool {
	_, err := os.Stat("/proc/sys/net/core/bpf_jit_enable")
	return err == nil
}

func (c Capability) String() string {
	return fmt.Sprintf("btf=%v objects=%d %s", c.HasBTF, len(c.Objects), c.Reason)
}

// Programs is the attach plan. Each entry maps a compiled object to the
// signals it produces. The agent exports only the aggregated signals.
var Programs = []Program{
	{Object: "sched_latency.bpf.o", Signals: []string{"runqlat_p99_us", "runqlat_node_p99_us"}, Attach: "tracepoint sched:sched_wakeup, sched:sched_switch"},
	{Object: "oom.bpf.o", Signals: []string{"oom_kills"}, Attach: "tracepoint oom:mark_victim"},
	{Object: "biolat.bpf.o", Signals: []string{"biolat_p99_us"}, Attach: "tracepoint block:block_rq_complete"},
	{Object: "tcp_retrans.bpf.o", Signals: []string{"tcp_retrans_rate"}, Attach: "tracepoint tcp:tcp_retransmit_skb"},
	{Object: "accept_overflow.bpf.o", Signals: []string{"accept_queue_drops"}, Attach: "kprobe tcp_v4_conn_request drop path / SNMP ListenDrops"},
	{Object: "dns_rtt.bpf.o", Signals: []string{"dns_latency_p99_us"}, Attach: "cgroup skb egress/ingress udp/53"},
}

type Program struct {
	Object  string
	Signals []string
	Attach  string
}
