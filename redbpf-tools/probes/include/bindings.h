#ifndef __VMLINUX_H__
// If __VMLINUX_H__ macro is not set, it means that redbpf-tools generates rust
// bindings of the Linux kernel structs using kernel headers.
#define KBUILD_MODNAME "cargo_bpf_bindings"
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
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#endif
