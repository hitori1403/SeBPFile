#pragma once

#include "types.h"
#include <linux/limits.h>

#define __u128(high, low) ((u128)high << 64 | low)

static inline u64 fnv1a(const __u8 *data, u32 len)
{
	u64 hash = 0xcbf29ce484222325;
	u64 fnv_prime = 0x00000100000001b3;

	while (len--) {
		hash ^= *data++;
		hash *= fnv_prime;
	}

	return hash;
}

static inline u128 fnv1a_128(const __u8 *data, __u32 len)
{
	u128 hash = __u128(0x6c62272e07bb0142, 0x62b821756295c58d);
	u128 fnv_prime = __u128(0x1000000, 0x13b);

	while (len--) {
		hash ^= *data++;
		hash *= fnv_prime;
	}

	return hash;
}

// NOTE: Temporatory function to bypass eBPF verifier as a workaround.
// This function may be removed in the future kernel versions.
static inline u64 fnv1a_path(const char *path)
{
	u64 hash = 0xcbf29ce484222325;
	u64 fnv_prime = 0x00000100000001b3;

	for (u32 i = 0; i < PATH_MAX; ++i) {
		if (!*path)
			break;

		hash ^= *path++;
		hash *= fnv_prime;
	}

	return hash;
}
