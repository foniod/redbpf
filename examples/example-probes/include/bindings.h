// include kernel headers here to generate rust bindings of kernel data types
// which are used by kprobe BPF programs.

#ifdef __VMLINUX_H__
// If __VMLINUX_H__ is defined, it means that this header file is included
// along with vmlinux.h
//
// vmlinux.h contains all types of the Linux kernel, so we don't have to
// include kernel headers in person here. But vmlinux.h does not include macro
// constants because BTF does not record them, thus macro constants are
// provided here by including some system headers or defining them directly.

#define NSEC_PER_MSEC 1000000L
#define NSEC_PER_USEC 1000L

#else
// use kernel headers
// Include required kernel headers here
#define BITS_PER_LONG 64
#include <linux/kconfig.h>
#include <linux/types.h>
#include <linux/math64.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/time64.h>

#endif
