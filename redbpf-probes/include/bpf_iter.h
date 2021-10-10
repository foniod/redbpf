#ifndef __BPF_ITER_H__
#define __BPF_ITER_H__
#undef bpf_iter__task
struct bpf_iter__task {
        union {
                struct bpf_iter_meta *meta;
        };
        union {
                struct task_struct *task;
        };
};
#endif  // __BPF_ITER_H__
