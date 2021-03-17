// include kernel headers here to generate rust bindings of kernel data types
// which are used by kprobe BPF programs.

#define BITS_PER_LONG 64
#include <linux/kconfig.h>
#include <linux/types.h>
#include <linux/math64.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/time64.h>
