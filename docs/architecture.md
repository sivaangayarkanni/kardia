# Architecture

Kardia explains production failures from kernel evidence. Application traces stop at the runtime. The failures that page an on-call — CFS throttle, OOM, reclaim stalls, disk p99, TCP loss, accept-queue drops, softirq drops, conntrack pressure — happen under that line.

```
node (Linux, Kubernetes worker, VM, bare metal)
  eBPF programs ──histogram / counter per cgroup per window──┐
  /proc pressure, SNMP, softnet, file-nr ────────────────────┤
                                                             ▼
                                                    agent (DaemonSet or systemd)
                                                    enrich cgroup → pod / VM
                                                    drop if cardinality budget exceeded
                                                             │
                                          POST /api/v1/ingest (1s batch)
                                                             ▼
                         analyzer replicas, consistent-hash by node
                         worker pool owns a node (order preserved)
                         rule engine → correlator → incident
                                                             │
                                                             ▼
                                              API + operator console + Prometheus
```

## What never crosses the node boundary

Raw trace events. A busy node can produce millions of scheduler wakeups a second. The agent exports one value per signal per entity per window. Default window is 1 second. That is the scalability boundary: analyzer cost grows with entities, not with events.

## Shard ownership

`-replicas` is the analyzer ring. A batch is accepted only by the replica that owns `batch.Node`. One owner means incident state does not split-brain. The in-process worker hash does the same thing inside a replica, so a node's windows stay ordered.

Backpressure is explicit. A full worker queue returns HTTP 429. The agent logs and drops that batch rather than stalling the eBPF reader. `kardia_batches_dropped_total` is the page.

## Platforms

| Surface | How the agent knows | What an explanation cites |
| --- | --- | --- |
| Kubernetes | downward API, cgroup path, pod list | namespace/pod, CPU limit vs node run queue |
| VM | DMI vendor, `KARDIA_VM_ID` | steal vs guest run queue, volume credit, ballooning |
| Bare metal | DMI is not a hypervisor | physical CPU, no steal-time caveat |
| Linux | fallback | node-scoped signals only |

A Kubernetes node that is also a VM keeps the VM id on the identity. The throttle explanation can then say the limit is the cause and the node is not saturated, which is the distinction that matters.

## Fault lifecycle

A ratio fault (throttle, disk, retransmits) must hold for 2 windows before an incident opens, and must stay quiet for 3 windows before it resolves. Discrete faults (OOM kill, accept-queue overflow) open on the first window. Updates keep the same incident id so the console does not flap.

## eBPF programs

| Object | Attach | Signal |
| --- | --- | --- |
| `sched_latency.bpf.c` | `sched_wakeup`, `sched_switch` | `runqlat_p99_us`, `runqlat_node_p99_us` |
| `oom.bpf.c` | `oom:mark_victim` | `oom_kills` |
| `biolat.bpf.c` | `block_rq_issue`, `block_rq_complete` | `biolat_p99_us` |
| `tcp_retrans.bpf.c` | `tcp:tcp_retransmit_skb` | `tcp_retrans_rate` |
| `dns_rtt.bpf.c` | cgroup skb UDP/53 | `dns_latency_p99_us` |

Programs are CO-RE. Build them on a host with BTF (`make bpf`). The agent probes `/sys/kernel/btf/vmlinux` and keeps the `/proc` collector running either way, so a node without BTF still explains pressure, retransmits, fd exhaustion, and conntrack.

## Durable store

The default store is in-memory and bounded (20k signals). `deploy/sql/schema.sql` is the Postgres record for multi-replica durability. Past a few thousand nodes, signals belong in a column store; incidents stay in Postgres. The diagnosis engine does not change between those backends.
