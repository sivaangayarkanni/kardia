# Signals

Agents export these names. Thresholds live in `diagnose.DefaultConfig`.

| Signal | Unit | Source | Used by |
| --- | --- | --- | --- |
| `runqlat_p99_us` | µs | eBPF sched | CFS throttle confirmation |
| `runqlat_node_p99_us` | µs | eBPF sched, cgroup 0 | CPU saturation vs throttle |
| `cpu_throttle_ratio` | ratio | cgroup cpu.stat | CFS throttle |
| `cpu_usage_ratio` | ratio | cgroup cpu.stat | context |
| `psi_cpu_some` / `psi_cpu_full` | percent | pressure | saturation |
| `psi_mem_some` / `psi_mem_full` | percent | pressure | reclaim stalls |
| `psi_io_some` / `psi_io_full` | percent | pressure | disk saturation |
| `oom_kills` | kills | eBPF oom:mark_victim | OOM |
| `mem_usage_ratio` | ratio | cgroup memory.current / max | OOM, pressure |
| `biolat_p99_us` | µs | eBPF block | disk saturation |
| `tcp_retrans_rate` | ratio | eBPF + SNMP | path loss |
| `accept_queue_drops` | drops | SNMP ListenDrops | accept overflow |
| `softnet_dropped` | packets | /proc/net/softnet_stat | NET_RX |
| `fd_usage_ratio` | ratio | file-nr | fd exhaustion |
| `dns_latency_p99_us` | µs | eBPF cgroup skb | DNS |
| `conntrack_usage_ratio` | ratio | nf_conntrack | conntrack pressure |
| `load1_per_cpu` | load | loadavg / ncpu | saturation context |

A rule that needs a signal does not fire when the signal is absent. Missing eBPF is silence, not a false incident.
