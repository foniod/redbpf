#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "redbpf_xdp"
#endif

#include <linux/kconfig.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#pragma clang diagnostic pop

#include <linux/skbuff.h>
