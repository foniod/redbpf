#include <linux/kconfig.h>
#include <linux/types.h>
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#endif

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "redbpf"
#endif

#include <linux/version.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/af_unix.h>
#include <linux/ipv6.h>
#include "xdp.h"
#include "bpf_iter.h"
