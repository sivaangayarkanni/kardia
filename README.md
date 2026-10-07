# Kardia

System-level incident diagnosis for Linux, Kubernetes, VMs, and bare metal. eBPF agents watch the kernel, aggregate on the node, and a sharded analyzer explains the incident in plain language with the evidence that produced it.

Application traces stop at the runtime. Kardia starts where they stop: CFS throttling, OOM, reclaim stalls, disk p99, TCP retransmits, accept-queue drops, NET_RX softirq, DNS RTT, conntrack pressure, file-descriptor exhaustion.

## What an incident looks like

A checkout pod is slow. CPU usage is flat at the limit, so HPA does not scale. Kardia opens:

> **CPU limit throttling pod checkout/checkout-api-7d4f**
> 47% of demanded CPU time was throttled. Node run-queue p99 is 220µs, so this is a limit, not host saturation. HPA on CPU usage will under-scale while throttled, because usage is capped at the limit.

The same engine distinguishes that from node saturation, from a VM whose volume credits are gone, and from a bare-metal load balancer whose accept queue is overflowing.

## Run it

```bash
go test ./...
go run ./cmd/kardia -mode=all -scenario=demo -listen=:8080
```

Open http://127.0.0.1:8080. The demo replays five production failures across Kubernetes, a cloud VM, and bare metal. `-scenario=off` diagnoses this host from `/proc` only.

```bash
curl -s localhost:8080/api/v1/incidents?status=open | jq
curl -s localhost:8080/metrics
```

## How it scales

Raw eBPF events never leave the node. The agent exports one value per signal per pod (or VM, or host) per 1 second window.

Analyzer replicas own a consistent-hash subset of nodes (`-replicas`). Inside a replica, a worker pool owns each node so windows stay ordered. A full queue returns 429; the agent drops the batch instead of stalling the kernel reader. Drops are `kardia_batches_dropped_total`.

| Piece | Role |
| --- | --- |
| `bpf/` | CO-RE programs: run queue, OOM, block latency, TCP retransmit, DNS RTT |
| `cmd/kardia` | agent, analyzer, or both |
| `internal/diagnose` | confirmation rules and the explanation |
| `internal/correlate` | open / update / resolve |
| `internal/pipeline` | sharded ingest, backpressure |
| `deploy/k8s` | DaemonSet + analyzer Deployment + HPA |
| `deploy/systemd` | bare metal and VM agent |
| `deploy/sql` | Postgres schema for durable incidents |

Kubernetes nodes that are also VMs keep both identities, so an explanation can say "the cgroup limit is the cause" and "the guest is not saturated" in the same incident.

## Build eBPF objects

On a Linux host with clang, libbpf headers, and kernel BTF:

```bash
make bpf
```

Without BTF the agent keeps the `/proc` collector (pressure, TCP SNMP, softnet, file-nr, conntrack) and says so in `/api/v1/status`. Missing probes are silence, not false incidents.

## API

| Method | Path | |
| --- | --- | --- |
| GET | `/` | operator console |
| GET | `/healthz` `/readyz` | probe |
| GET | `/metrics` | Prometheus |
| GET | `/api/v1/status` | pipeline, store, eBPF probe |
| GET | `/api/v1/incidents?status=open` | list |
| GET | `/api/v1/incidents/{id}` | one incident |
| POST | `/api/v1/ingest` | agent batch |
| GET | `/api/v1/stream` | server-sent incident updates |

## License

MIT.
