/* SPDX-License-Identifier: GPL-2.0 */
/* Common CO-RE helpers. Production builds generate vmlinux.h with
 * `bpftool btf dump file /sys/kernel/btf/vmlinux format c`. The programs in
 * this directory use stable tracepoint argument layouts so they also compile
 * against the kernel UAPI headers shipped with libbpf. */
#ifndef KARDIA_BPF_COMMON_H
#define KARDIA_BPF_COMMON_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define WINDOW_NS (1000000000ull)

struct signal_key {
	__u64 cgroup_id;
	__u32 pid;
	__u32 pad;
};

struct hist {
	__u64 buckets[36]; /* log2 latency in microseconds */
	__u64 count;
	__u64 sum_us;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); /* pid or cgroup */
	__type(value, __u64); /* timestamp ns */
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64); /* cgroup id, 0 = node */
	__type(value, struct hist);
} latency SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

struct event {
	__u64 cgroup_id;
	__u32 pid;
	__u32 kind; /* 1 oom, 2 retrans, 3 accept drop */
	__u64 value;
	char comm[16];
};

static __always_inline void hist_add(__u64 cgroup_id, __u64 us)
{
	struct hist *h = bpf_map_lookup_elem(&latency, &cgroup_id);
	if (!h) {
		struct hist zero = {};
		bpf_map_update_elem(&latency, &cgroup_id, &zero, BPF_NOEXIST);
		h = bpf_map_lookup_elem(&latency, &cgroup_id);
		if (!h)
			return;
	}
	__u32 slot = 0;
	__u64 v = us;
	while (v > 1 && slot < 35) {
		v >>= 1;
		slot++;
	}
	__sync_fetch_and_add(&h->buckets[slot], 1);
	__sync_fetch_and_add(&h->count, 1);
	__sync_fetch_and_add(&h->sum_us, us);
}

#endif
