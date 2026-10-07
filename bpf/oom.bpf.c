/* SPDX-License-Identifier: GPL-2.0 */
/* OOM victim marker. One ringbuf event per kill. The agent counts these per
 * cgroup per window and exports oom_kills. Discrete events open an incident
 * on the first window. */
#include "common.h"

struct oom_mark_victim_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	int common_pid;
	__u32 pid;
	char comm[16];
};

SEC("tp/oom/mark_victim")
int kardia_oom(struct oom_mark_victim_args *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->pid = ctx->pid;
	e->kind = 1;
	e->value = 1;
	__builtin_memcpy(e->comm, ctx->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
