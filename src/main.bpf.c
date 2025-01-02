#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/limits.h>

#include "constants.h"

#include "chacha20.bpf.c"
#include "helpers.bpf.c"
#include "fnv1a.c"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 1024

struct transfer_state {
	u32 fd;
	u64 offset;
	u8 *buf;
	u32 buf_sz;
	u64 path_hash;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct transfer_state);
} map_transfer_state SEC(".maps");

struct fd_info {
	u64 offset;
	u64 path_hash;
	u8 perm;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct fd_info);
} map_fd_info SEC(".maps");

struct proc_info {
	s32 uid;
	s32 pid;
	s32 ppid;
	const char cwd[PATH_MAX];
	const char path[PATH_MAX];
	u8 perm;
	u8 log;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64); // TODO: u128
	__type(value, struct proc_info[MAX_PROCESSES_PER_FILE]);
} map_path_rules SEC(".maps");

struct key_info {
	u64 hash;
	unsigned char key[KEY_LENGTH_MAX];
	unsigned char nonce[NONCE_LENGTH_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64); // TODO: u128
	__type(value, struct key_info);
} map_keys SEC(".maps");

const volatile int loader_pid = 0;

// NOTE: Using smaller size in newer kernel version if possible
/* char target_proc_cwd[PATH_MAX + NAME_MAX]; */
char target_proc_cwd[65536];
char target_proc_path[65536];

u32 target_proc_cwd_len = 0;
u32 target_proc_pid = 0;

int target_proc_cwd_mtx = 0;
int target_proc_path_mtx = 0;

int get_proc_cwd(struct trace_event_raw_sys_enter *ctx);
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(u32));
	__array(values, int(void *));
} map_progs SEC(".maps") = {
	.values = {
		[0] = (void *)&get_proc_cwd,
		[1] = (void *)&handle_enter_openat,
	},
};

SEC("tp/syscalls/sys_enter_openat")
int get_proc_path(struct trace_event_raw_sys_enter *ctx)
{
	if (target_proc_path_mtx && target_proc_pid)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct dentry *dentry = BPF_CORE_READ(task, mm, exe_file, f_path.dentry);

	target_proc_pid = bpf_get_current_pid_tgid();

	get_d_path(target_proc_path, dentry);
	target_proc_path_mtx = 1;

	bpf_tail_call(ctx, &map_progs, 0);

	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int get_proc_cwd(struct trace_event_raw_sys_enter *ctx)
{
	if (!target_proc_path_mtx || target_proc_cwd_mtx)
		return 0;

	u32 pid = bpf_get_current_pid_tgid();
	if (pid != target_proc_pid)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct dentry *dentry = BPF_CORE_READ(task, fs, pwd.dentry);

	target_proc_cwd_len = get_d_path(target_proc_cwd, dentry);

	target_proc_cwd[target_proc_cwd_len] = '/';
	++target_proc_cwd_len;

	target_proc_cwd_mtx = 1;

	bpf_tail_call(ctx, &map_progs, 1);

	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	// if both path isn't fully retrieved
	if (!target_proc_path_mtx || !target_proc_cwd_mtx)
		return 0;

	u32 pid = bpf_get_current_pid_tgid();
	if (pid == loader_pid || pid != target_proc_pid)
		goto mtx_cleanup;

	if (target_proc_cwd_len >= PATH_MAX)
		return 0;

	// BUG: https://github.com/iovisor/bcc/issues/3175
	s32 retval = bpf_probe_read_user_str(target_proc_cwd + target_proc_cwd_len, PATH_MAX,
					     (char *)ctx->args[1]);
	if (retval < 0)
		return 0;

	if (target_proc_cwd_len >= PATH_MAX)
		return 0;

	char *file_path = target_proc_cwd;
	if (target_proc_cwd[target_proc_cwd_len] == '/')
		file_path += target_proc_cwd_len;

	// TODO: using u128 for improved hash collision resistance
	/* u128 etc_passwd = __u128(0x1b1181c0cded9454, 0x60a4d74db663e357); */
	// TODO: handle path traversal ./ ../ ../../
	u64 path_hash = fnv1a_path(file_path);

	struct proc_info *procs = bpf_map_lookup_elem(&map_path_rules, &path_hash);
	if (!procs)
		return 0;

	struct key_info *param = bpf_map_lookup_elem(&map_keys, &path_hash);
	if (!param) {
		bpf_printk("missing key & nonce for: %s", file_path);
		return 0;
	}

	u32 uid = bpf_get_current_uid_gid();
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	u32 ppid = BPF_CORE_READ(task, real_parent, pid);

	for (u32 i = 0; i < MAX_PROCESSES_PER_FILE; ++i) {
		if (!procs[i].path[0])
			break;

		if (procs[i].pid > 0 && procs[i].pid != pid)
			continue;

		if (procs[i].ppid > 0 && procs[i].ppid != ppid)
			continue;

		if (procs[i].uid >= 0 && procs[i].uid != uid)
			continue;

		struct pathcmp_cb_ctx cb_ctx = { (char *)procs[i].path, target_proc_path, 0 };
		bpf_loop(PATH_MAX, pathcmp_cb, &cb_ctx, 0);

		if (cb_ctx.result)
			continue;

		/* log(path_buf, procs[i].path, "ALLOW", "OPEN"); */
		bpf_printk("file: %s, process: %s, pid: %d, ALLOW on OPEN operation", file_path,
			   procs[i].path, pid);

		u64 pid_fd = (u64)pid << 32;
		struct fd_info fdi = { 0, path_hash, procs[i].perm };

		bpf_map_update_elem(&map_fd_info, &pid_fd, &fdi, BPF_ANY);

		goto mtx_cleanup;
	}

	/* log(path_buf, proc_path, "BLOCK", "OPEN"); */
	bpf_printk("file: %s, process: %s, pid: %d, BLOCK on OPEN operation", file_path,
		   target_proc_path, pid);

	bpf_send_signal(9);

mtx_cleanup:
	target_proc_cwd_mtx = 0;
	target_proc_path_mtx = 0;
	target_proc_pid = 0;

	return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 pid_fd = (u64)pid << 32;

	struct fd_info *fdi = bpf_map_lookup_elem(&map_fd_info, &pid_fd);
	if (!fdi) {
		/* bpf_printk("[sys_exit_openat] pid %d, missing fd info", pid); */
		return 0;
	}

	struct fd_info transfer_fdi = { 0, fdi->path_hash, fdi->perm };

	bpf_map_delete_elem(&map_fd_info, &pid_fd);

	u32 fd = ctx->ret;
	if (fd <= 0) {
		bpf_printk("[sys_exit_openat] pid %d, ret <= 0", pid);
		return 0;
	}

	pid_fd |= fd;

	bpf_map_update_elem(&map_fd_info, &pid_fd, &transfer_fdi, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_enter_lseek")
int handle_enter_lseek(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u32 fd = ctx->args[0];
	u64 pid_fd = (u64)pid << 32 | fd;

	struct fd_info *fdi = bpf_map_lookup_elem(&map_fd_info, &pid_fd);
	if (!fdi) {
		/* bpf_printk("[sys_enter_lseek] pid %d, missing fd info", pid); */
		return 0;
	}

	struct transfer_state state = { fd, 0, 0, 0, fdi->path_hash };
	bpf_map_update_elem(&map_transfer_state, &pid, &state, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_exit_lseek")
int handle_exit_lseek(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	struct transfer_state *state = bpf_map_lookup_elem(&map_transfer_state, &pid);
	if (!state) {
		/* bpf_printk("[sys_exit_lseek] pid %d, missing transfer state", pid); */
		return 0;
	}

	u64 pid_fd = (u64)pid << 32 | state->fd;

	struct fd_info *fdi = bpf_map_lookup_elem(&map_fd_info, &pid_fd);
	if (!fdi) {
		bpf_printk("[sys_exit_lseek] pid %d, missing fd info", pid);
		return 0;
	}

	if (ctx->ret < 0) {
		bpf_printk("[sys_exit_lseek] pid %d, missing ret < 0", pid);
		return 0;
	}

	u64 current_offset = ctx->ret;
	struct fd_info new_fdi = { current_offset, state->path_hash, fdi->perm };

	bpf_map_update_elem(&map_fd_info, &pid_fd, &new_fdi, BPF_EXIST);
	bpf_map_delete_elem(&map_transfer_state, &pid);

	return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	u32 fd = ctx->args[0];

	u64 pid_fd = (u64)pid << 32 | fd;

	struct fd_info *fdi = bpf_map_lookup_elem(&map_fd_info, &pid_fd);
	if (!fdi) {
		/* bpf_printk("[sys_enter_read] pid %d, missing fd info", pid); */
		return 0;
	}

	if (!(fdi->perm & 4)) {
		bpf_printk("pid %d is not allowed to read", pid);
		return 0;
	}

	struct transfer_state state = { fd, fdi->offset, (u8 *)ctx->args[1], 0, fdi->path_hash };
	bpf_map_update_elem(&map_transfer_state, &pid, &state, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();

	struct transfer_state *state = bpf_map_lookup_elem(&map_transfer_state, &pid);
	if (!state) {
		/* bpf_printk("[sys_exit_read] pid %d, missing transfer state", pid); */
		return 0;
	}

	struct key_info *param = bpf_map_lookup_elem(&map_keys, &state->path_hash);
	if (!param) {
		bpf_printk("[sys_exit_read] pid %d, missing chacha20 params", pid);
		return 0;
	}

	u64 pid_fd = (u64)pid << 32 | state->fd;

	struct fd_info *fdi = bpf_map_lookup_elem(&map_fd_info, &pid_fd);
	if (!fdi) {
		bpf_printk("[sys_exit_read] pid %d, missing fd info", pid);
		return 0;
	}

	u32 bytes_read = ctx->ret;
	if (bytes_read <= 0) {
		bpf_printk("[sys_exit_read] pid %d, bytes read <= 0", pid);
		goto cleanup;
	}

	u32 counter = (state->offset + 63) >> 6;
	u8 skip = state->offset % 64;
	chacha20_docrypt_user(state->buf, bytes_read, param->key, param->nonce, counter, skip);

	state->offset += bytes_read;

	struct fd_info new_fdi = { state->offset, state->path_hash, fdi->perm };
	bpf_map_update_elem(&map_fd_info, &pid_fd, &new_fdi, BPF_EXIST);

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

	struct fd_info *fdi = bpf_map_lookup_elem(&map_fd_info, &pid_fd);
	if (!fdi) {
		/* bpf_printk("[sys_enter_write] pid %d, missing fd info", pid); */
		return 0;
	}

	if (!(fdi->perm & 2)) {
		bpf_printk("pid %d is not allowed to write", pid);
		return 0;
	}

	struct key_info *param = bpf_map_lookup_elem(&map_keys, &fdi->path_hash);
	if (!param) {
		bpf_printk("[sys_enter_write] pid %d, missing chacha20 params", pid);
		return 0;
	}

	u32 count = ctx->args[2];
	if (count <= 0) {
		bpf_printk("[sys_enter_write] pid %d, count <= 0", pid);
		return 0;
	}

	struct transfer_state state = { fd, fdi->offset, (u8 *)ctx->args[1], count,
					fdi->path_hash };
	bpf_map_update_elem(&map_transfer_state, &pid, &state, BPF_ANY);

	u32 counter = (state.offset + 63) >> 6;
	u8 skip = state.offset % 64;
	chacha20_docrypt_user(state.buf, count, param->key, param->nonce, counter, skip);

	return 0;
}

SEC("tp/syscalls/sys_exit_write")
int handle_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();

	struct transfer_state *state = bpf_map_lookup_elem(&map_transfer_state, &pid);
	if (!state) {
		/* bpf_printk("[sys_exit_write] pid %d, missing transfer state", pid); */
		return 0;
	}

	struct key_info *param = bpf_map_lookup_elem(&map_keys, &state->path_hash);
	if (!param) {
		bpf_printk("[sys_exit_write] pid %d, missing chacha20 params", pid);
		return 0;
	}

	u64 pid_fd = (u64)pid << 32 | state->fd;

	struct fd_info *fdi = bpf_map_lookup_elem(&map_fd_info, &pid_fd);
	if (!fdi) {
		bpf_printk("[sys_exit_write] pid %d, missing fd info", pid);
		return 0;
	}

	u32 bytes_written = ctx->ret;
	if (bytes_written <= 0) {
		bpf_printk("[sys_exit_write] pid %d, bytes written <= 0", pid);
		goto cleanup;
	}

	u32 counter = (state->offset + 63) >> 6;
	u8 skip = state->offset % 64;
	chacha20_docrypt_user(state->buf, state->buf_sz, param->key, param->nonce, counter, skip);

	state->offset += bytes_written;

	struct fd_info new_fdi = { state->offset, state->path_hash, fdi->perm };
	bpf_map_update_elem(&map_fd_info, &pid_fd, &new_fdi, BPF_EXIST);

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

	bpf_map_delete_elem(&map_fd_info, &pid_fd);

	return 0;
}
