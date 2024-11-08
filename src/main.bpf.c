#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/limits.h>

#include "chacha20.bpf.c"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct transfer_state {
	u32 fd;
	u64 offset;
	u8 *buf;
	u32 buf_sz;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256 * 1024);
	__type(key, u32);
	__type(value, struct transfer_state);
} map_transfer_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256 * 1024);
	__type(key, u64);
	__type(value, u64);
} map_fd_offset SEC(".maps");

const volatile int loader_pid = 0;
const volatile int filename_len = 0;
const volatile char filename[PATH_MAX];

char path_buf[PATH_MAX];

SEC("tp/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	if (pid == loader_pid)
		return 0;

	// BUG: https://github.com/iovisor/bcc/issues/3175
	s32 retcode = bpf_probe_read_user_str(path_buf, PATH_MAX, (char *)ctx->args[1]);
	if (retcode < 0)
		return 0;

	for (int i = 0; i < filename_len; ++i) {
		if (filename[i] != path_buf[i])
			return 0;
	}

	u64 pid_fd = (u64)pid << 32;
	u64 zero = 0;

	bpf_map_update_elem(&map_fd_offset, &pid_fd, &zero, BPF_ANY);

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
