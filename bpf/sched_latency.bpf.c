/* SPDX-License-Identifier: GPL-2.0 */
/* Run-queue latency. Records the delay between sched_wakeup and the matching
 * sched_switch onto that task. Userspace reads the per-cgroup histogram once
 * per window and exports runqlat_p99_us. Node scope is cgroup id 0. */
#include "common.h"

struct sched_wakeup_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	int common_pid;
	char comm[16];
	__u32 pid;
	int prio;
	int target_cpu;
};

struct sched_switch_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	int common_pid;
	char prev_comm[16];
	__u32 prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	__u32 next_pid;
	int next_prio;
};

SEC("tp/sched/sched_wakeup")
int kardia_wakeup(struct sched_wakeup_args *ctx)
{
	__u64 pid = ctx->pid;
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &pid, &now, BPF_ANY);
	return 0;
}

SEC("tp/sched/sched_switch")
int kardia_switch(struct sched_switch_args *ctx)
{
	__u64 pid = ctx->next_pid;
	__u64 *start = bpf_map_lookup_elem(&starts, &pid);
	if (!start)
		return 0;
	__u64 dt = bpf_ktime_get_ns() - *start;
	bpf_map_delete_elem(&starts, &pid);
	__u64 us = dt / 1000;
	__u64 cg = bpf_get_current_cgroup_id();
	hist_add(cg, us);
	hist_add(0, us);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
