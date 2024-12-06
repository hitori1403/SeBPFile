#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/limits.h>

#include "constants.h"

#include "chacha20.bpf.c"
#include "fnv1a.c"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 1024

struct transfer_state {
	u32 fd;
	u64 offset;
	u8 *buf;
	u32 buf_sz;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct transfer_state);
} map_transfer_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} map_fd_offset SEC(".maps");

struct proc_info {
	u32 uid;
	u32 pid;
	u32 ppid;
	const char cwd[PATH_MAX];
	const char path[PATH_MAX];
	u8 perm;
	u8 log;
};

struct key_info {
	u64 hash;
	char key[KEY_LENGTH_MAX];
	char nonce[KEY_LENGTH_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64); // TODO: u128
	__type(value, struct proc_info[MAX_PROCESSES_PER_FILE]);
} map_path_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64); // TODO: u128
	__type(value, struct key_info);
} map_keys SEC(".maps");

const volatile int loader_pid = 0;

char path_buf[PATH_MAX];
char tmp[PATH_MAX];

// NOTE: Using smaller size in newer kernel version if possible
/* char process_path[PATH_MAX + NAME_MAX]; */
char proc_path[65536];

int proc_path_mtx = 0;

struct cb_pathcmp_ctx {
	char *s1;
	char *s2;
	u8 result;
};

// the equal case is sufficient
static int cb_pathcmp(u32 i, struct cb_pathcmp_ctx *ctx)
{
	if (i >= PATH_MAX)
		return 1;

	if (ctx->s1[i] != ctx->s2[i]) {
		ctx->result = 1;
		return 1;
	}

	if (!ctx->s1[i]) {
		ctx->result = 0;
		return 1;
	}

	return 0;
}

struct cb_strrev_ctx {
	char *s;
	u16 pos;
	u16 len;
};

static int cb_strrev(u32 idx, struct cb_strrev_ctx *ctx)
{
	u16 left = ctx->pos + idx;
	u16 right = ctx->pos + ctx->len - idx - 1;

	if (left >= PATH_MAX || right >= PATH_MAX)
		return 1;

	u8 tmp = ctx->s[left];
	ctx->s[left] = ctx->s[right];
	ctx->s[right] = tmp;

	return 0;
}

static int get_d_path(char *buf, struct task_struct *task)
{
	char *name;
	u16 buf_len = 0;
	struct dentry *dentry = BPF_CORE_READ(task, mm, exe_file, f_path.dentry);

	for (u32 i = 0; i < PATH_MAX / 2; ++i) {
		bpf_core_read(&name, sizeof(name), &dentry->d_name.name);

		if (buf_len >= PATH_MAX - 1)
			break;

		u16 len = bpf_probe_read_kernel_str(&buf[buf_len], NAME_MAX, name) - 1;

		if (buf_len >= PATH_MAX || buf[buf_len] == '/') {
			buf[buf_len] = 0; // remove last slash
			break;
		}

		struct cb_strrev_ctx cb_ctx = { buf, buf_len, len };
		bpf_loop(len / 2, (void *)cb_strrev, &cb_ctx, 0);

		buf_len += len;

		if (buf_len < PATH_MAX)
			buf[buf_len] = '/';

		++buf_len;

		dentry = BPF_CORE_READ(dentry, d_parent);
	}

	struct cb_strrev_ctx cb_ctx = { buf, 0, buf_len };
	bpf_loop(buf_len / 2, (void *)cb_strrev, &cb_ctx, 0);

	return buf_len;
}

static void log(const char *file, const char *process, char *action, char *operation)
{
	bpf_printk("File %s - Process %s: %s on %s operation", file, process, action, operation);
}

SEC("tp/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	if (pid == loader_pid)
		return 0;

	if (!proc_path_mtx)
		return 0;

	// BUG: https://github.com/iovisor/bcc/issues/3175
	s32 retcode = bpf_probe_read_user_str(path_buf, PATH_MAX, (char *)ctx->args[1]);
	if (retcode < 0)
		return 0;
	bpf_probe_read_user_str(tmp, PATH_MAX, (char *)ctx->args[1]);

	// TODO: using u128 for improved hash collision resistance
	/* u128 etc_passwd = __u128(0x1b1181c0cded9454, 0x60a4d74db663e357); */

	u64 path_hash = fnv1a_path(path_buf);

	struct proc_info *procs = bpf_map_lookup_elem(&map_path_rules, &path_hash);

	if (!procs)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	for (u32 i = 0; i < MAX_PROCESSES_PER_FILE; ++i) {
		if (!procs[i].path[0]) {
			break;
		}

		struct cb_pathcmp_ctx cb_ctx = { (char *)procs[i].path, proc_path, 0 };
		bpf_loop(PATH_MAX, cb_pathcmp, &cb_ctx, 0);

		if (cb_ctx.result)
			continue;

		log(tmp, procs[i].path, "ALLOW", "OPEN");

		u64 pid_fd = (u64)pid << 32;
		u64 zero = 0;

		bpf_map_update_elem(&map_fd_offset, &pid_fd, &zero, BPF_ANY);
		proc_path_mtx = 0;

		return 0;
	}

	log(tmp, proc_path, "BLOCK", "OPEN");

	// TODO: handle SIGKILL
	/* bpf_send_signal(9); */
	proc_path_mtx = 0;

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(u32));
	__array(values, int(void *));
} map_progs SEC(".maps") = {
	.values = {
		[1] = (void *)&handle_enter_openat,
	},
};

SEC("tp/syscalls/sys_enter_openat")
int get_proc_path(struct trace_event_raw_sys_enter *ctx)
{
	if (proc_path_mtx)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	get_d_path(proc_path, task);
	proc_path_mtx = 1;
	bpf_tail_call(ctx, &map_progs, 1);

	return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 pid_fd = (u64)pid << 32;

	void *exist = bpf_map_lookup_elem(&map_fd_offset, &pid_fd);
	if (!exist)
		return 0;

	bpf_map_delete_elem(&map_fd_offset, &pid_fd);

	u32 fd = ctx->ret;
	if (fd <= 0)
		return 0;

	pid_fd |= fd;
	u64 zero = 0;

	bpf_map_update_elem(&map_fd_offset, &pid_fd, &zero, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_enter_lseek")
int handle_enter_lseek(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u32 fd = ctx->args[0];
	u64 pid_fd = (u64)pid << 32 | fd;

	u64 *offset = bpf_map_lookup_elem(&map_fd_offset, &pid_fd);
	if (!offset)
		return 0;

	struct transfer_state state = { fd, 0, 0 };
	bpf_map_update_elem(&map_transfer_state, &pid, &state, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_exit_lseek")
int handle_exit_lseek(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	struct transfer_state *state = bpf_map_lookup_elem(&map_transfer_state, &pid);
	if (!state)
		return 0;

	if (ctx->ret < 0)
		return 0;

	u64 current_offset = ctx->ret;
	u64 pid_fd = (u64)pid << 32 | state->fd;
	bpf_map_update_elem(&map_fd_offset, &pid_fd, &current_offset, BPF_EXIST);

	bpf_map_delete_elem(&map_transfer_state, &pid);

	return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u32 fd = ctx->args[0];

	u64 pid_fd = (u64)pid << 32 | fd;

	u64 *offset = bpf_map_lookup_elem(&map_fd_offset, &pid_fd);
	if (!offset)
		return 0;

	struct transfer_state state = { fd, *offset, (u8 *)ctx->args[1] };
	bpf_map_update_elem(&map_transfer_state, &pid, &state, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();

	struct transfer_state *state = bpf_map_lookup_elem(&map_transfer_state, &pid);
	if (!state)
		return 0;

	u32 bytes_read = ctx->ret;
	if (bytes_read <= 0)
		goto cleanup;

	u32 counter = (state->offset + 63) >> 6;
	u8 skip = state->offset % 64;
	chacha20_docrypt_user(state->buf, bytes_read, (u8 *)key, (u8 *)nonce, counter, skip);

	state->offset += bytes_read;

	u64 pid_fd = (u64)pid << 32 | state->fd;
	bpf_map_update_elem(&map_fd_offset, &pid_fd, &state->offset, BPF_EXIST);

cleanup:
	bpf_map_delete_elem(&map_transfer_state, &pid);

	return 0;
}

SEC("tp/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u32 fd = ctx->args[0];

	u64 pid_fd = (u64)pid << 32 | fd;

	u64 *offset = bpf_map_lookup_elem(&map_fd_offset, &pid_fd);
	if (!offset)
		return 0;

	u32 count = ctx->args[2];
	if (count <= 0)
		return 0;

	struct transfer_state state = { fd, *offset, (u8 *)ctx->args[1], count };
	bpf_map_update_elem(&map_transfer_state, &pid, &state, BPF_ANY);

	u32 counter = (state.offset + 63) >> 6;
	u8 skip = state.offset % 64;
	chacha20_docrypt_user(state.buf, count, (u8 *)key, (u8 *)nonce, counter, skip);

	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int handle_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();

	struct transfer_state *state = bpf_map_lookup_elem(&map_transfer_state, &pid);
	if (!state)
		return 0;

	u32 bytes_written = ctx->ret;
	if (bytes_written <= 0)
		goto cleanup;

	u32 counter = (state->offset + 63) >> 6;
	u8 skip = state->offset % 64;
	chacha20_docrypt_user(state->buf, state->buf_sz, (u8 *)key, (u8 *)nonce, counter, skip);

	state->offset += bytes_written;

	u64 pid_fd = (u64)pid << 32 | state->fd;
	bpf_map_update_elem(&map_fd_offset, &pid_fd, &state->offset, BPF_EXIST);

cleanup:
	bpf_map_delete_elem(&map_transfer_state, &pid);

	return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u32 fd = ctx->args[0];
	u64 pid_fd = (u64)pid << 32 | fd;

	bpf_map_delete_elem(&map_fd_offset, &pid_fd);

	return 0;
}
