//! This is an example of showing difference between `PerCpuHashMap` and
//! `HashMap`. The former is per-cpu data structure and users don't need to
//! worry about race condition. The latter is global data structure so it has
//! race condition problems.
//!
//! `PerCpuArray` can be used instead of bpf stack to hold temporary values
//! that exceeds the maximum size of bpf stack (512 bytes).
#![no_std]
#![no_main]
use example_probes::hashmaps::*;
use redbpf_probes::kprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut ALT_STACK: PerCpuArray<BigStructure> = PerCpuArray::with_max_entries(1);

#[map]
static mut BIG_STRUCT: LruHashMap<i8, BigStructure> = LruHashMap::with_max_entries(16);

#[map]
static mut PCPU_MEM_ALLOC: PerCpuHashMap<usize, usize> = PerCpuHashMap::with_max_entries(16);

#[map]
static mut MEM_ALLOC: HashMap<usize, usize> = HashMap::with_max_entries(16);

#[kprobe]
unsafe fn sched_fork(_regs: Registers) {
    let rnd_key = (bpf_get_prandom_u32() & 0xff) as i8;
    if let Some(bigstruct) = BIG_STRUCT.get_mut(&rnd_key) {
        bigstruct.f2[99] = 99;
        BIG_STRUCT.set(&rnd_key, bigstruct);
    } else {
        // maximum size of bpf stack is 512 bytes. BigStructure struct is 808
        // bytes. So it can not be located in stack. Use percpu array to hold
        // temporary BigStructure value. Note that if percpu array is used for
        // this purpose, the size of percpu array must be 1. This is checked by
        // BPF verifier.
        let bigstruct = ALT_STACK.get_mut(0).unwrap();
        for x in 0..=99 {
            bigstruct.f2[x] = x;
        }

        BIG_STRUCT.set(&rnd_key, bigstruct);
    }
}

#[kprobe]
unsafe fn __kmalloc(regs: Registers) {
    let mut size = regs.parm1() as usize;
    let mut max: usize = 9999;
    for x in 1..=12 {
        size >>= 1;
        if size == 0 {
            max = usize::pow(2, x) - 1;
            break;
        }
    }
    if let Some(count) = PCPU_MEM_ALLOC.get_mut(&max) {
        *count += 1;
        let count = MEM_ALLOC.get_mut(&max).unwrap();
        *count += 1;
    } else {
        let count = 1;
        PCPU_MEM_ALLOC.set(&max, &count);
        MEM_ALLOC.set(&max, &count);
    }
}
