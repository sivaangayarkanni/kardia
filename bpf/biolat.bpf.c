/* SPDX-License-Identifier: GPL-2.0 */
/* Block request completion latency. Userspace computes biolat_p99_us per
 * cgroup. On a VM this is the guest block layer (virtio or nvme). */
#include "common.h"

struct block_rq_complete_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	int common_pid;
	__u32 dev;
	__u64 sector;
	__u32 nr_sector;
	int error;
	char rwbs[8];
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64); /* sector-ish request key filled by block_rq_issue */
	__type(value, __u64);
} rq_start SEC(".maps");

struct block_rq_issue_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	int common_pid;
	__u32 dev;
	__u64 sector;
	__u32 nr_sector;
	__u32 bytes;
	char rwbs[8];
	char comm[16];
	char cmd[];
};

SEC("tp/block/block_rq_issue")
int kardia_rq_issue(struct block_rq_issue_args *ctx)
{
	__u64 key = ((__u64)ctx->dev << 32) ^ ctx->sector;
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&rq_start, &key, &now, BPF_ANY);
	return 0;
}

SEC("tp/block/block_rq_complete")
int kardia_rq_complete(struct block_rq_complete_args *ctx)
{
	__u64 key = ((__u64)ctx->dev << 32) ^ ctx->sector;
	__u64 *start = bpf_map_lookup_elem(&rq_start, &key);
	if (!start)
		return 0;
	__u64 us = (bpf_ktime_get_ns() - *start) / 1000;
	bpf_map_delete_elem(&rq_start, &key);
	hist_add(bpf_get_current_cgroup_id(), us);
	hist_add(0, us);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
