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

#undef bpf_iter_meta
struct bpf_iter_meta {
        union {
                struct seq_file *seq;
        };
        u64 session_id;
        u64 seq_num;
};

#endif  // __BPF_ITER_H__
