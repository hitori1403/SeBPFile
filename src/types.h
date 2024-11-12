#pragma once

#include <asm-generic/int-ll64.h>

// https://elixir.bootlin.com/linux/v6.12-rc6/source/include/asm-generic/int-ll64.h

#ifndef __ASSEMBLY__

typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

#endif

// https://elixir.bootlin.com/linux/v6.12-rc6/source/include/uapi/linux/types.h

#ifdef __SIZEOF_INT128__
typedef __signed__ __int128 __s128 __attribute__((aligned(16)));
typedef unsigned __int128 __u128 __attribute__((aligned(16)));
#endif

// https://elixir.bootlin.com/linux/v6.12-rc6/source/include/linux/types.h

#ifdef __SIZEOF_INT128__
typedef __s128 s128;
typedef __u128 u128;
#endif
