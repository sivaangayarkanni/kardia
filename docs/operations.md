# Operations

## Local

```
go test ./...
go run ./cmd/kardia -mode=all -scenario=demo -listen=:8080
```

Open http://127.0.0.1:8080. Within a few seconds the demo opens incidents for a throttled checkout pod, a payments OOM, a VM volume with exhausted IOPS credits, a bare-metal accept-queue overflow, and node conntrack pressure. They resolve after the scripted window ends.

`-scenario=off` collects only this host (`/proc/pressure`, TCP SNMP, softnet, file-nr, conntrack).

## Node agent

Kubernetes: `kubectl apply -f deploy/k8s/kardia.yaml`. The DaemonSet needs `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE`, host `/sys` and `/proc`, and the node name from the downward API.

Bare metal and VMs: `deploy/systemd/kardia-agent.service`. Set `KARDIA_PLATFORM=vm` and `KARDIA_VM_ID` on cloud guests so explanations mention steal time and volume credits instead of physical saturation.

## Scaling

- One agent per node. It aggregates. It does not stream events.
- Analyzer replicas own a subset of nodes via `-replicas`. Scale the Deployment; keep the ring in agreement.
- HPA in the manifest scales analyzers on CPU. Queue drops (`kardia_batches_dropped_total`) mean add replicas or raise `-queue`, not that the agent should retry forever.
- Cardinality: one series per entity per signal per window. A 5,000 node cluster with 30 pods per node and 15 signals is about 2 million values per window before compression, which is why the agent batches and the store keeps a ring, not a raw trace.

## Compiling eBPF

On a Linux builder with clang and libbpf headers:

```
make bpf
```

Objects go to `bpf/out`. The agent logs whether BTF and objects are present. Diagnosis still runs on `/proc` if they are not.
