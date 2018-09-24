#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

extern crate zero;
pub mod perf_reader;

pub const BUF_SIZE_MAP_NS: usize = 256;
pub struct bpf_map_def {
	  pub kind: u32,
	  pub key_size: u32,
	  pub value_size: u32,
	  pub max_entries: u32,
	  pub map_flags: u32,
	  pub pinning: u32,
	  pub namespace: [i8; BUF_SIZE_MAP_NS]
}
unsafe impl ::zero::Pod for bpf_map_def {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage, Align>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    storage: Storage,
    align: [Align; 0],
}

impl<Storage, Align> __BindgenBitfieldUnit<Storage, Align>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn new(storage: Storage) -> Self {
        Self { storage, align: [] }
    }

    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());

        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];

        let bit_index = index % 8;
        let mask = 1 << bit_index;

        byte & mask == mask
    }

    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());

        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];

        let bit_index = index % 8;
        let mask = 1 << bit_index;

        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }

    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());

        let mut val = 0;

        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                val |= 1 << i;
            }
        }

        val
    }

    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());

        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            self.set_bit(i + bit_offset, val_bit_is_set);
        }
    }
}
#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData)
    }
    #[inline]
    pub unsafe fn as_ptr(&self) -> *const T {
        ::std::mem::transmute(self)
    }
    #[inline]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
        ::std::mem::transmute(self)
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
impl<T> ::std::clone::Clone for __IncompleteArrayField<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new()
    }
}
impl<T> ::std::marker::Copy for __IncompleteArrayField<T> {}
pub const BPF_LD: u32 = 0;
pub const BPF_LDX: u32 = 1;
pub const BPF_ST: u32 = 2;
pub const BPF_STX: u32 = 3;
pub const BPF_ALU: u32 = 4;
pub const BPF_JMP: u32 = 5;
pub const BPF_RET: u32 = 6;
pub const BPF_MISC: u32 = 7;
pub const BPF_W: u32 = 0;
pub const BPF_H: u32 = 8;
pub const BPF_B: u32 = 16;
pub const BPF_IMM: u32 = 0;
pub const BPF_ABS: u32 = 32;
pub const BPF_IND: u32 = 64;
pub const BPF_MEM: u32 = 96;
pub const BPF_LEN: u32 = 128;
pub const BPF_MSH: u32 = 160;
pub const BPF_ADD: u32 = 0;
pub const BPF_SUB: u32 = 16;
pub const BPF_MUL: u32 = 32;
pub const BPF_DIV: u32 = 48;
pub const BPF_OR: u32 = 64;
pub const BPF_AND: u32 = 80;
pub const BPF_LSH: u32 = 96;
pub const BPF_RSH: u32 = 112;
pub const BPF_NEG: u32 = 128;
pub const BPF_MOD: u32 = 144;
pub const BPF_XOR: u32 = 160;
pub const BPF_JA: u32 = 0;
pub const BPF_JEQ: u32 = 16;
pub const BPF_JGT: u32 = 32;
pub const BPF_JGE: u32 = 48;
pub const BPF_JSET: u32 = 64;
pub const BPF_K: u32 = 0;
pub const BPF_X: u32 = 8;
pub const BPF_MAXINSNS: u32 = 4096;
pub const BPF_ALU64: u32 = 7;
pub const BPF_DW: u32 = 24;
pub const BPF_XADD: u32 = 192;
pub const BPF_MOV: u32 = 176;
pub const BPF_ARSH: u32 = 192;
pub const BPF_END: u32 = 208;
pub const BPF_TO_LE: u32 = 0;
pub const BPF_TO_BE: u32 = 8;
pub const BPF_FROM_LE: u32 = 0;
pub const BPF_FROM_BE: u32 = 8;
pub const BPF_JNE: u32 = 80;
pub const BPF_JLT: u32 = 160;
pub const BPF_JLE: u32 = 176;
pub const BPF_JSGT: u32 = 96;
pub const BPF_JSGE: u32 = 112;
pub const BPF_JSLT: u32 = 192;
pub const BPF_JSLE: u32 = 208;
pub const BPF_CALL: u32 = 128;
pub const BPF_EXIT: u32 = 144;
pub const BPF_F_ALLOW_OVERRIDE: u32 = 1;
pub const BPF_F_ALLOW_MULTI: u32 = 2;
pub const BPF_F_STRICT_ALIGNMENT: u32 = 1;
pub const BPF_PSEUDO_MAP_FD: u32 = 1;
pub const BPF_PSEUDO_CALL: u32 = 1;
pub const BPF_ANY: u32 = 0;
pub const BPF_NOEXIST: u32 = 1;
pub const BPF_EXIST: u32 = 2;
pub const BPF_F_NO_PREALLOC: u32 = 1;
pub const BPF_F_NO_COMMON_LRU: u32 = 2;
pub const BPF_F_NUMA_NODE: u32 = 4;
pub const BPF_F_QUERY_EFFECTIVE: u32 = 1;
pub const BPF_OBJ_NAME_LEN: u32 = 16;
pub const BPF_F_RDONLY: u32 = 8;
pub const BPF_F_WRONLY: u32 = 16;
pub const BPF_F_STACK_BUILD_ID: u32 = 32;
pub const BPF_BUILD_ID_SIZE: u32 = 20;
pub const BPF_F_RECOMPUTE_CSUM: u32 = 1;
pub const BPF_F_INVALIDATE_HASH: u32 = 2;
pub const BPF_F_HDR_FIELD_MASK: u32 = 15;
pub const BPF_F_PSEUDO_HDR: u32 = 16;
pub const BPF_F_MARK_MANGLED_0: u32 = 32;
pub const BPF_F_MARK_ENFORCE: u32 = 64;
pub const BPF_F_INGRESS: u32 = 1;
pub const BPF_F_TUNINFO_IPV6: u32 = 1;
pub const BPF_F_SKIP_FIELD_MASK: u32 = 255;
pub const BPF_F_USER_STACK: u32 = 256;
pub const BPF_F_FAST_STACK_CMP: u32 = 512;
pub const BPF_F_REUSE_STACKID: u32 = 1024;
pub const BPF_F_USER_BUILD_ID: u32 = 2048;
pub const BPF_F_ZERO_CSUM_TX: u32 = 2;
pub const BPF_F_DONT_FRAGMENT: u32 = 4;
pub const BPF_F_SEQ_NUMBER: u32 = 8;
pub const BPF_F_INDEX_MASK: u32 = 4294967295;
pub const BPF_F_CURRENT_CPU: u32 = 4294967295;
pub const BPF_F_CTXLEN_MASK: u64 = 4503595332403200;
pub const BPF_TAG_SIZE: u32 = 8;
pub const BPF_SOCK_OPS_RTO_CB_FLAG: u32 = 1;
pub const BPF_SOCK_OPS_RETRANS_CB_FLAG: u32 = 2;
pub const BPF_SOCK_OPS_STATE_CB_FLAG: u32 = 4;
pub const BPF_SOCK_OPS_ALL_CB_FLAGS: u32 = 7;
pub const BPF_DEVCG_ACC_MKNOD: u32 = 1;
pub const BPF_DEVCG_ACC_READ: u32 = 2;
pub const BPF_DEVCG_ACC_WRITE: u32 = 4;
pub const BPF_DEVCG_DEV_BLOCK: u32 = 1;
pub const BPF_DEVCG_DEV_CHAR: u32 = 2;
pub const BPF_FN_PREFIX: &'static [u8; 9usize] = b".bpf.fn.\0";
pub type __u8 = ::std::os::raw::c_uchar;
pub type __s16 = ::std::os::raw::c_short;
pub type __u16 = ::std::os::raw::c_ushort;
pub type __s32 = ::std::os::raw::c_int;
pub type __u32 = ::std::os::raw::c_uint;
pub type __u64 = ::std::os::raw::c_ulonglong;
pub type __kernel_ulong_t = ::std::os::raw::c_ulong;
pub type __kernel_pid_t = ::std::os::raw::c_int;
pub type __kernel_size_t = __kernel_ulong_t;
pub type __be16 = __u16;
pub type __be32 = __u32;
pub type pid_t = __kernel_pid_t;
pub const BPF_REG_0: _bindgen_ty_2 = 0;
pub const BPF_REG_1: _bindgen_ty_2 = 1;
pub const BPF_REG_2: _bindgen_ty_2 = 2;
pub const BPF_REG_3: _bindgen_ty_2 = 3;
pub const BPF_REG_4: _bindgen_ty_2 = 4;
pub const BPF_REG_5: _bindgen_ty_2 = 5;
pub const BPF_REG_6: _bindgen_ty_2 = 6;
pub const BPF_REG_7: _bindgen_ty_2 = 7;
pub const BPF_REG_8: _bindgen_ty_2 = 8;
pub const BPF_REG_9: _bindgen_ty_2 = 9;
pub const BPF_REG_10: _bindgen_ty_2 = 10;
pub const __MAX_BPF_REG: _bindgen_ty_2 = 11;
pub type _bindgen_ty_2 = u32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_insn {
    pub code: __u8,
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize], u8>,
    pub off: __s16,
    pub imm: __s32,
}
#[test]
fn bindgen_test_layout_bpf_insn() {
    assert_eq!(
        ::std::mem::size_of::<bpf_insn>(),
        8usize,
        concat!("Size of: ", stringify!(bpf_insn))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_insn>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_insn))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_insn>())).code as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_insn),
            "::",
            stringify!(code)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_insn>())).off as *const _ as usize },
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_insn),
            "::",
            stringify!(off)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_insn>())).imm as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_insn),
            "::",
            stringify!(imm)
        )
    );
}
impl bpf_insn {
    #[inline]
    pub fn dst_reg(&self) -> __u8 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_dst_reg(&mut self, val: __u8) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn src_reg(&self) -> __u8 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_src_reg(&mut self, val: __u8) {
        unsafe {
            let val: u8 = ::std::mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(dst_reg: __u8, src_reg: __u8) -> __BindgenBitfieldUnit<[u8; 1usize], u8> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 1usize], u8> =
            Default::default();
        __bindgen_bitfield_unit.set(0usize, 4u8, {
            let dst_reg: u8 = unsafe { ::std::mem::transmute(dst_reg) };
            dst_reg as u64
        });
        __bindgen_bitfield_unit.set(4usize, 4u8, {
            let src_reg: u8 = unsafe { ::std::mem::transmute(src_reg) };
            src_reg as u64
        });
        __bindgen_bitfield_unit
    }
}
unsafe impl ::zero::Pod for bpf_insn {}

#[repr(C)]
#[derive(Debug)]
pub struct bpf_lpm_trie_key {
    pub prefixlen: __u32,
    pub data: __IncompleteArrayField<__u8>,
}
#[test]
fn bindgen_test_layout_bpf_lpm_trie_key() {
    assert_eq!(
        ::std::mem::size_of::<bpf_lpm_trie_key>(),
        4usize,
        concat!("Size of: ", stringify!(bpf_lpm_trie_key))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_lpm_trie_key>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_lpm_trie_key))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_lpm_trie_key>())).prefixlen as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_lpm_trie_key),
            "::",
            stringify!(prefixlen)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_lpm_trie_key>())).data as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_lpm_trie_key),
            "::",
            stringify!(data)
        )
    );
}
pub const bpf_cmd_BPF_MAP_CREATE: bpf_cmd = 0;
pub const bpf_cmd_BPF_MAP_LOOKUP_ELEM: bpf_cmd = 1;
pub const bpf_cmd_BPF_MAP_UPDATE_ELEM: bpf_cmd = 2;
pub const bpf_cmd_BPF_MAP_DELETE_ELEM: bpf_cmd = 3;
pub const bpf_cmd_BPF_MAP_GET_NEXT_KEY: bpf_cmd = 4;
pub const bpf_cmd_BPF_PROG_LOAD: bpf_cmd = 5;
pub const bpf_cmd_BPF_OBJ_PIN: bpf_cmd = 6;
pub const bpf_cmd_BPF_OBJ_GET: bpf_cmd = 7;
pub const bpf_cmd_BPF_PROG_ATTACH: bpf_cmd = 8;
pub const bpf_cmd_BPF_PROG_DETACH: bpf_cmd = 9;
pub const bpf_cmd_BPF_PROG_TEST_RUN: bpf_cmd = 10;
pub const bpf_cmd_BPF_PROG_GET_NEXT_ID: bpf_cmd = 11;
pub const bpf_cmd_BPF_MAP_GET_NEXT_ID: bpf_cmd = 12;
pub const bpf_cmd_BPF_PROG_GET_FD_BY_ID: bpf_cmd = 13;
pub const bpf_cmd_BPF_MAP_GET_FD_BY_ID: bpf_cmd = 14;
pub const bpf_cmd_BPF_OBJ_GET_INFO_BY_FD: bpf_cmd = 15;
pub const bpf_cmd_BPF_PROG_QUERY: bpf_cmd = 16;
pub const bpf_cmd_BPF_RAW_TRACEPOINT_OPEN: bpf_cmd = 17;
pub const bpf_cmd_BPF_BTF_LOAD: bpf_cmd = 18;
pub const bpf_cmd_BPF_BTF_GET_FD_BY_ID: bpf_cmd = 19;
pub const bpf_cmd_BPF_TASK_FD_QUERY: bpf_cmd = 20;
pub type bpf_cmd = u32;
pub const bpf_map_type_BPF_MAP_TYPE_UNSPEC: bpf_map_type = 0;
pub const bpf_map_type_BPF_MAP_TYPE_HASH: bpf_map_type = 1;
pub const bpf_map_type_BPF_MAP_TYPE_ARRAY: bpf_map_type = 2;
pub const bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY: bpf_map_type = 3;
pub const bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY: bpf_map_type = 4;
pub const bpf_map_type_BPF_MAP_TYPE_PERCPU_HASH: bpf_map_type = 5;
pub const bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY: bpf_map_type = 6;
pub const bpf_map_type_BPF_MAP_TYPE_STACK_TRACE: bpf_map_type = 7;
pub const bpf_map_type_BPF_MAP_TYPE_CGROUP_ARRAY: bpf_map_type = 8;
pub const bpf_map_type_BPF_MAP_TYPE_LRU_HASH: bpf_map_type = 9;
pub const bpf_map_type_BPF_MAP_TYPE_LRU_PERCPU_HASH: bpf_map_type = 10;
pub const bpf_map_type_BPF_MAP_TYPE_LPM_TRIE: bpf_map_type = 11;
pub const bpf_map_type_BPF_MAP_TYPE_ARRAY_OF_MAPS: bpf_map_type = 12;
pub const bpf_map_type_BPF_MAP_TYPE_HASH_OF_MAPS: bpf_map_type = 13;
pub const bpf_map_type_BPF_MAP_TYPE_DEVMAP: bpf_map_type = 14;
pub const bpf_map_type_BPF_MAP_TYPE_SOCKMAP: bpf_map_type = 15;
pub const bpf_map_type_BPF_MAP_TYPE_CPUMAP: bpf_map_type = 16;
pub const bpf_map_type_BPF_MAP_TYPE_XSKMAP: bpf_map_type = 17;
pub const bpf_map_type_BPF_MAP_TYPE_SOCKHASH: bpf_map_type = 18;
pub type bpf_map_type = u32;
pub const bpf_prog_type_BPF_PROG_TYPE_UNSPEC: bpf_prog_type = 0;
pub const bpf_prog_type_BPF_PROG_TYPE_SOCKET_FILTER: bpf_prog_type = 1;
pub const bpf_prog_type_BPF_PROG_TYPE_KPROBE: bpf_prog_type = 2;
pub const bpf_prog_type_BPF_PROG_TYPE_SCHED_CLS: bpf_prog_type = 3;
pub const bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT: bpf_prog_type = 4;
pub const bpf_prog_type_BPF_PROG_TYPE_TRACEPOINT: bpf_prog_type = 5;
pub const bpf_prog_type_BPF_PROG_TYPE_XDP: bpf_prog_type = 6;
pub const bpf_prog_type_BPF_PROG_TYPE_PERF_EVENT: bpf_prog_type = 7;
pub const bpf_prog_type_BPF_PROG_TYPE_CGROUP_SKB: bpf_prog_type = 8;
pub const bpf_prog_type_BPF_PROG_TYPE_CGROUP_SOCK: bpf_prog_type = 9;
pub const bpf_prog_type_BPF_PROG_TYPE_LWT_IN: bpf_prog_type = 10;
pub const bpf_prog_type_BPF_PROG_TYPE_LWT_OUT: bpf_prog_type = 11;
pub const bpf_prog_type_BPF_PROG_TYPE_LWT_XMIT: bpf_prog_type = 12;
pub const bpf_prog_type_BPF_PROG_TYPE_SOCK_OPS: bpf_prog_type = 13;
pub const bpf_prog_type_BPF_PROG_TYPE_SK_SKB: bpf_prog_type = 14;
pub const bpf_prog_type_BPF_PROG_TYPE_CGROUP_DEVICE: bpf_prog_type = 15;
pub const bpf_prog_type_BPF_PROG_TYPE_SK_MSG: bpf_prog_type = 16;
pub const bpf_prog_type_BPF_PROG_TYPE_RAW_TRACEPOINT: bpf_prog_type = 17;
pub const bpf_prog_type_BPF_PROG_TYPE_CGROUP_SOCK_ADDR: bpf_prog_type = 18;
pub const bpf_prog_type_BPF_PROG_TYPE_LWT_SEG6LOCAL: bpf_prog_type = 19;
pub const bpf_prog_type_BPF_PROG_TYPE_LIRC_MODE2: bpf_prog_type = 20;
pub type bpf_prog_type = u32;
pub const bpf_attach_type_BPF_CGROUP_INET_INGRESS: bpf_attach_type = 0;
pub const bpf_attach_type_BPF_CGROUP_INET_EGRESS: bpf_attach_type = 1;
pub const bpf_attach_type_BPF_CGROUP_INET_SOCK_CREATE: bpf_attach_type = 2;
pub const bpf_attach_type_BPF_CGROUP_SOCK_OPS: bpf_attach_type = 3;
pub const bpf_attach_type_BPF_SK_SKB_STREAM_PARSER: bpf_attach_type = 4;
pub const bpf_attach_type_BPF_SK_SKB_STREAM_VERDICT: bpf_attach_type = 5;
pub const bpf_attach_type_BPF_CGROUP_DEVICE: bpf_attach_type = 6;
pub const bpf_attach_type_BPF_SK_MSG_VERDICT: bpf_attach_type = 7;
pub const bpf_attach_type_BPF_CGROUP_INET4_BIND: bpf_attach_type = 8;
pub const bpf_attach_type_BPF_CGROUP_INET6_BIND: bpf_attach_type = 9;
pub const bpf_attach_type_BPF_CGROUP_INET4_CONNECT: bpf_attach_type = 10;
pub const bpf_attach_type_BPF_CGROUP_INET6_CONNECT: bpf_attach_type = 11;
pub const bpf_attach_type_BPF_CGROUP_INET4_POST_BIND: bpf_attach_type = 12;
pub const bpf_attach_type_BPF_CGROUP_INET6_POST_BIND: bpf_attach_type = 13;
pub const bpf_attach_type_BPF_CGROUP_UDP4_SENDMSG: bpf_attach_type = 14;
pub const bpf_attach_type_BPF_CGROUP_UDP6_SENDMSG: bpf_attach_type = 15;
pub const bpf_attach_type_BPF_LIRC_MODE2: bpf_attach_type = 16;
pub const bpf_attach_type___MAX_BPF_ATTACH_TYPE: bpf_attach_type = 17;
pub type bpf_attach_type = u32;
pub const bpf_stack_build_id_status_BPF_STACK_BUILD_ID_EMPTY: bpf_stack_build_id_status = 0;
pub const bpf_stack_build_id_status_BPF_STACK_BUILD_ID_VALID: bpf_stack_build_id_status = 1;
pub const bpf_stack_build_id_status_BPF_STACK_BUILD_ID_IP: bpf_stack_build_id_status = 2;
pub type bpf_stack_build_id_status = u32;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_stack_build_id {
    pub status: __s32,
    pub build_id: [::std::os::raw::c_uchar; 20usize],
    pub __bindgen_anon_1: bpf_stack_build_id__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_stack_build_id__bindgen_ty_1 {
    pub offset: __u64,
    pub ip: __u64,
    _bindgen_union_align: u64,
}
#[test]
fn bindgen_test_layout_bpf_stack_build_id__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<bpf_stack_build_id__bindgen_ty_1>(),
        8usize,
        concat!("Size of: ", stringify!(bpf_stack_build_id__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_stack_build_id__bindgen_ty_1>(),
        8usize,
        concat!(
            "Alignment of ",
            stringify!(bpf_stack_build_id__bindgen_ty_1)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_stack_build_id__bindgen_ty_1>())).offset as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_stack_build_id__bindgen_ty_1),
            "::",
            stringify!(offset)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_stack_build_id__bindgen_ty_1>())).ip as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_stack_build_id__bindgen_ty_1),
            "::",
            stringify!(ip)
        )
    );
}
#[test]
fn bindgen_test_layout_bpf_stack_build_id() {
    assert_eq!(
        ::std::mem::size_of::<bpf_stack_build_id>(),
        32usize,
        concat!("Size of: ", stringify!(bpf_stack_build_id))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_stack_build_id>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_stack_build_id))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_stack_build_id>())).status as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_stack_build_id),
            "::",
            stringify!(status)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_stack_build_id>())).build_id as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_stack_build_id),
            "::",
            stringify!(build_id)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr {
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_1,
    pub __bindgen_anon_2: bpf_attr__bindgen_ty_2,
    pub __bindgen_anon_3: bpf_attr__bindgen_ty_3,
    pub __bindgen_anon_4: bpf_attr__bindgen_ty_4,
    pub __bindgen_anon_5: bpf_attr__bindgen_ty_5,
    pub test: bpf_attr__bindgen_ty_6,
    pub __bindgen_anon_6: bpf_attr__bindgen_ty_7,
    pub info: bpf_attr__bindgen_ty_8,
    pub query: bpf_attr__bindgen_ty_9,
    pub raw_tracepoint: bpf_attr__bindgen_ty_10,
    pub __bindgen_anon_7: bpf_attr__bindgen_ty_11,
    pub task_fd_query: bpf_attr__bindgen_ty_12,
    _bindgen_union_align: [u64; 9usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_1 {
    pub map_type: __u32,
    pub key_size: __u32,
    pub value_size: __u32,
    pub max_entries: __u32,
    pub map_flags: __u32,
    pub inner_map_fd: __u32,
    pub numa_node: __u32,
    pub map_name: [::std::os::raw::c_char; 16usize],
    pub map_ifindex: __u32,
    pub btf_fd: __u32,
    pub btf_key_type_id: __u32,
    pub btf_value_type_id: __u32,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_1>(),
        60usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_1>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_1))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).map_type as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(map_type)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).key_size as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(key_size)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).value_size as *const _ as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(value_size)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).max_entries as *const _ as usize
        },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(max_entries)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).map_flags as *const _ as usize
        },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(map_flags)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).inner_map_fd as *const _ as usize
        },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(inner_map_fd)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).numa_node as *const _ as usize
        },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(numa_node)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).map_name as *const _ as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(map_name)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).map_ifindex as *const _ as usize
        },
        44usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(map_ifindex)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).btf_fd as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(btf_fd)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).btf_key_type_id as *const _ as usize
        },
        52usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(btf_key_type_id)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_1>())).btf_value_type_id as *const _
                as usize
        },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_1),
            "::",
            stringify!(btf_value_type_id)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_attr__bindgen_ty_2 {
    pub map_fd: __u32,
    pub key: __u64,
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_2__bindgen_ty_1,
    pub flags: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_2__bindgen_ty_1 {
    pub value: __u64,
    pub next_key: __u64,
    _bindgen_union_align: u64,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_2__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_2__bindgen_ty_1>(),
        8usize,
        concat!(
            "Size of: ",
            stringify!(bpf_attr__bindgen_ty_2__bindgen_ty_1)
        )
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_2__bindgen_ty_1>(),
        8usize,
        concat!(
            "Alignment of ",
            stringify!(bpf_attr__bindgen_ty_2__bindgen_ty_1)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_2__bindgen_ty_1>())).value as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_2__bindgen_ty_1),
            "::",
            stringify!(value)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_2__bindgen_ty_1>())).next_key as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_2__bindgen_ty_1),
            "::",
            stringify!(next_key)
        )
    );
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_2() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_2>(),
        32usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_2))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_2>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_2))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_2>())).map_fd as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_2),
            "::",
            stringify!(map_fd)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_2>())).key as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_2),
            "::",
            stringify!(key)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_2>())).flags as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_2),
            "::",
            stringify!(flags)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_3 {
    pub prog_type: __u32,
    pub insn_cnt: __u32,
    pub insns: __u64,
    pub license: __u64,
    pub log_level: __u32,
    pub log_size: __u32,
    pub log_buf: __u64,
    pub kern_version: __u32,
    pub prog_flags: __u32,
    pub prog_name: [::std::os::raw::c_char; 16usize],
    pub prog_ifindex: __u32,
    pub expected_attach_type: __u32,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_3() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_3>(),
        72usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_3))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_3>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_3))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).prog_type as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(prog_type)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).insn_cnt as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(insn_cnt)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).insns as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(insns)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).license as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(license)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).log_level as *const _ as usize
        },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(log_level)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).log_size as *const _ as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(log_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).log_buf as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(log_buf)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).kern_version as *const _ as usize
        },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(kern_version)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).prog_flags as *const _ as usize
        },
        44usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(prog_flags)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).prog_name as *const _ as usize
        },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(prog_name)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).prog_ifindex as *const _ as usize
        },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(prog_ifindex)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_3>())).expected_attach_type as *const _
                as usize
        },
        68usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_3),
            "::",
            stringify!(expected_attach_type)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_4 {
    pub pathname: __u64,
    pub bpf_fd: __u32,
    pub file_flags: __u32,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_4() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_4>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_4))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_4>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_4))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_4>())).pathname as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_4),
            "::",
            stringify!(pathname)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_4>())).bpf_fd as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_4),
            "::",
            stringify!(bpf_fd)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_4>())).file_flags as *const _ as usize
        },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_4),
            "::",
            stringify!(file_flags)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_5 {
    pub target_fd: __u32,
    pub attach_bpf_fd: __u32,
    pub attach_type: __u32,
    pub attach_flags: __u32,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_5() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_5>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_5))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_5>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_5))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_5>())).target_fd as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_5),
            "::",
            stringify!(target_fd)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_5>())).attach_bpf_fd as *const _ as usize
        },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_5),
            "::",
            stringify!(attach_bpf_fd)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_5>())).attach_type as *const _ as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_5),
            "::",
            stringify!(attach_type)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_5>())).attach_flags as *const _ as usize
        },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_5),
            "::",
            stringify!(attach_flags)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_6 {
    pub prog_fd: __u32,
    pub retval: __u32,
    pub data_size_in: __u32,
    pub data_size_out: __u32,
    pub data_in: __u64,
    pub data_out: __u64,
    pub repeat: __u32,
    pub duration: __u32,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_6() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_6>(),
        40usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_6))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_6>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_6))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_6>())).prog_fd as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_6),
            "::",
            stringify!(prog_fd)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_6>())).retval as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_6),
            "::",
            stringify!(retval)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_6>())).data_size_in as *const _ as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_6),
            "::",
            stringify!(data_size_in)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_6>())).data_size_out as *const _ as usize
        },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_6),
            "::",
            stringify!(data_size_out)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_6>())).data_in as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_6),
            "::",
            stringify!(data_in)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_6>())).data_out as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_6),
            "::",
            stringify!(data_out)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_6>())).repeat as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_6),
            "::",
            stringify!(repeat)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_6>())).duration as *const _ as usize },
        36usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_6),
            "::",
            stringify!(duration)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_attr__bindgen_ty_7 {
    pub __bindgen_anon_1: bpf_attr__bindgen_ty_7__bindgen_ty_1,
    pub next_id: __u32,
    pub open_flags: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr__bindgen_ty_7__bindgen_ty_1 {
    pub start_id: __u32,
    pub prog_id: __u32,
    pub map_id: __u32,
    pub btf_id: __u32,
    _bindgen_union_align: u32,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_7__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_7__bindgen_ty_1>(),
        4usize,
        concat!(
            "Size of: ",
            stringify!(bpf_attr__bindgen_ty_7__bindgen_ty_1)
        )
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_7__bindgen_ty_1>(),
        4usize,
        concat!(
            "Alignment of ",
            stringify!(bpf_attr__bindgen_ty_7__bindgen_ty_1)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_7__bindgen_ty_1>())).start_id as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_7__bindgen_ty_1),
            "::",
            stringify!(start_id)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_7__bindgen_ty_1>())).prog_id as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_7__bindgen_ty_1),
            "::",
            stringify!(prog_id)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_7__bindgen_ty_1>())).map_id as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_7__bindgen_ty_1),
            "::",
            stringify!(map_id)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_7__bindgen_ty_1>())).btf_id as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_7__bindgen_ty_1),
            "::",
            stringify!(btf_id)
        )
    );
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_7() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_7>(),
        12usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_7))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_7>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_7))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_7>())).next_id as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_7),
            "::",
            stringify!(next_id)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_7>())).open_flags as *const _ as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_7),
            "::",
            stringify!(open_flags)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_8 {
    pub bpf_fd: __u32,
    pub info_len: __u32,
    pub info: __u64,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_8() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_8>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_8))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_8>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_8))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_8>())).bpf_fd as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_8),
            "::",
            stringify!(bpf_fd)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_8>())).info_len as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_8),
            "::",
            stringify!(info_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_8>())).info as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_8),
            "::",
            stringify!(info)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_9 {
    pub target_fd: __u32,
    pub attach_type: __u32,
    pub query_flags: __u32,
    pub attach_flags: __u32,
    pub prog_ids: __u64,
    pub prog_cnt: __u32,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_9() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_9>(),
        32usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_9))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_9>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_9))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_9>())).target_fd as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_9),
            "::",
            stringify!(target_fd)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_9>())).attach_type as *const _ as usize
        },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_9),
            "::",
            stringify!(attach_type)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_9>())).query_flags as *const _ as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_9),
            "::",
            stringify!(query_flags)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_9>())).attach_flags as *const _ as usize
        },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_9),
            "::",
            stringify!(attach_flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_9>())).prog_ids as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_9),
            "::",
            stringify!(prog_ids)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_9>())).prog_cnt as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_9),
            "::",
            stringify!(prog_cnt)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_10 {
    pub name: __u64,
    pub prog_fd: __u32,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_10() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_10>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_10))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_10>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_10))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_10>())).name as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_10),
            "::",
            stringify!(name)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_10>())).prog_fd as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_10),
            "::",
            stringify!(prog_fd)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_11 {
    pub btf: __u64,
    pub btf_log_buf: __u64,
    pub btf_size: __u32,
    pub btf_log_size: __u32,
    pub btf_log_level: __u32,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_11() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_11>(),
        32usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_11))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_11>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_11))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_11>())).btf as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_11),
            "::",
            stringify!(btf)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_11>())).btf_log_buf as *const _ as usize
        },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_11),
            "::",
            stringify!(btf_log_buf)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_11>())).btf_size as *const _ as usize
        },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_11),
            "::",
            stringify!(btf_size)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_11>())).btf_log_size as *const _ as usize
        },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_11),
            "::",
            stringify!(btf_log_size)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_11>())).btf_log_level as *const _ as usize
        },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_11),
            "::",
            stringify!(btf_log_level)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_attr__bindgen_ty_12 {
    pub pid: __u32,
    pub fd: __u32,
    pub flags: __u32,
    pub buf_len: __u32,
    pub buf: __u64,
    pub prog_id: __u32,
    pub fd_type: __u32,
    pub probe_offset: __u64,
    pub probe_addr: __u64,
}
#[test]
fn bindgen_test_layout_bpf_attr__bindgen_ty_12() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr__bindgen_ty_12>(),
        48usize,
        concat!("Size of: ", stringify!(bpf_attr__bindgen_ty_12))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr__bindgen_ty_12>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr__bindgen_ty_12))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_12>())).pid as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_12),
            "::",
            stringify!(pid)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_12>())).fd as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_12),
            "::",
            stringify!(fd)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_12>())).flags as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_12),
            "::",
            stringify!(flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_12>())).buf_len as *const _ as usize },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_12),
            "::",
            stringify!(buf_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_12>())).buf as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_12),
            "::",
            stringify!(buf)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_12>())).prog_id as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_12),
            "::",
            stringify!(prog_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr__bindgen_ty_12>())).fd_type as *const _ as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_12),
            "::",
            stringify!(fd_type)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_12>())).probe_offset as *const _ as usize
        },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_12),
            "::",
            stringify!(probe_offset)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_attr__bindgen_ty_12>())).probe_addr as *const _ as usize
        },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr__bindgen_ty_12),
            "::",
            stringify!(probe_addr)
        )
    );
}
#[test]
fn bindgen_test_layout_bpf_attr() {
    assert_eq!(
        ::std::mem::size_of::<bpf_attr>(),
        72usize,
        concat!("Size of: ", stringify!(bpf_attr))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_attr>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_attr))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr>())).test as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr),
            "::",
            stringify!(test)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr>())).info as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr),
            "::",
            stringify!(info)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr>())).query as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr),
            "::",
            stringify!(query)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr>())).raw_tracepoint as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr),
            "::",
            stringify!(raw_tracepoint)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_attr>())).task_fd_query as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_attr),
            "::",
            stringify!(task_fd_query)
        )
    );
}
pub const bpf_func_id_BPF_FUNC_unspec: bpf_func_id = 0;
pub const bpf_func_id_BPF_FUNC_map_lookup_elem: bpf_func_id = 1;
pub const bpf_func_id_BPF_FUNC_map_update_elem: bpf_func_id = 2;
pub const bpf_func_id_BPF_FUNC_map_delete_elem: bpf_func_id = 3;
pub const bpf_func_id_BPF_FUNC_probe_read: bpf_func_id = 4;
pub const bpf_func_id_BPF_FUNC_ktime_get_ns: bpf_func_id = 5;
pub const bpf_func_id_BPF_FUNC_trace_printk: bpf_func_id = 6;
pub const bpf_func_id_BPF_FUNC_get_prandom_u32: bpf_func_id = 7;
pub const bpf_func_id_BPF_FUNC_get_smp_processor_id: bpf_func_id = 8;
pub const bpf_func_id_BPF_FUNC_skb_store_bytes: bpf_func_id = 9;
pub const bpf_func_id_BPF_FUNC_l3_csum_replace: bpf_func_id = 10;
pub const bpf_func_id_BPF_FUNC_l4_csum_replace: bpf_func_id = 11;
pub const bpf_func_id_BPF_FUNC_tail_call: bpf_func_id = 12;
pub const bpf_func_id_BPF_FUNC_clone_redirect: bpf_func_id = 13;
pub const bpf_func_id_BPF_FUNC_get_current_pid_tgid: bpf_func_id = 14;
pub const bpf_func_id_BPF_FUNC_get_current_uid_gid: bpf_func_id = 15;
pub const bpf_func_id_BPF_FUNC_get_current_comm: bpf_func_id = 16;
pub const bpf_func_id_BPF_FUNC_get_cgroup_classid: bpf_func_id = 17;
pub const bpf_func_id_BPF_FUNC_skb_vlan_push: bpf_func_id = 18;
pub const bpf_func_id_BPF_FUNC_skb_vlan_pop: bpf_func_id = 19;
pub const bpf_func_id_BPF_FUNC_skb_get_tunnel_key: bpf_func_id = 20;
pub const bpf_func_id_BPF_FUNC_skb_set_tunnel_key: bpf_func_id = 21;
pub const bpf_func_id_BPF_FUNC_perf_event_read: bpf_func_id = 22;
pub const bpf_func_id_BPF_FUNC_redirect: bpf_func_id = 23;
pub const bpf_func_id_BPF_FUNC_get_route_realm: bpf_func_id = 24;
pub const bpf_func_id_BPF_FUNC_perf_event_output: bpf_func_id = 25;
pub const bpf_func_id_BPF_FUNC_skb_load_bytes: bpf_func_id = 26;
pub const bpf_func_id_BPF_FUNC_get_stackid: bpf_func_id = 27;
pub const bpf_func_id_BPF_FUNC_csum_diff: bpf_func_id = 28;
pub const bpf_func_id_BPF_FUNC_skb_get_tunnel_opt: bpf_func_id = 29;
pub const bpf_func_id_BPF_FUNC_skb_set_tunnel_opt: bpf_func_id = 30;
pub const bpf_func_id_BPF_FUNC_skb_change_proto: bpf_func_id = 31;
pub const bpf_func_id_BPF_FUNC_skb_change_type: bpf_func_id = 32;
pub const bpf_func_id_BPF_FUNC_skb_under_cgroup: bpf_func_id = 33;
pub const bpf_func_id_BPF_FUNC_get_hash_recalc: bpf_func_id = 34;
pub const bpf_func_id_BPF_FUNC_get_current_task: bpf_func_id = 35;
pub const bpf_func_id_BPF_FUNC_probe_write_user: bpf_func_id = 36;
pub const bpf_func_id_BPF_FUNC_current_task_under_cgroup: bpf_func_id = 37;
pub const bpf_func_id_BPF_FUNC_skb_change_tail: bpf_func_id = 38;
pub const bpf_func_id_BPF_FUNC_skb_pull_data: bpf_func_id = 39;
pub const bpf_func_id_BPF_FUNC_csum_update: bpf_func_id = 40;
pub const bpf_func_id_BPF_FUNC_set_hash_invalid: bpf_func_id = 41;
pub const bpf_func_id_BPF_FUNC_get_numa_node_id: bpf_func_id = 42;
pub const bpf_func_id_BPF_FUNC_skb_change_head: bpf_func_id = 43;
pub const bpf_func_id_BPF_FUNC_xdp_adjust_head: bpf_func_id = 44;
pub const bpf_func_id_BPF_FUNC_probe_read_str: bpf_func_id = 45;
pub const bpf_func_id_BPF_FUNC_get_socket_cookie: bpf_func_id = 46;
pub const bpf_func_id_BPF_FUNC_get_socket_uid: bpf_func_id = 47;
pub const bpf_func_id_BPF_FUNC_set_hash: bpf_func_id = 48;
pub const bpf_func_id_BPF_FUNC_setsockopt: bpf_func_id = 49;
pub const bpf_func_id_BPF_FUNC_skb_adjust_room: bpf_func_id = 50;
pub const bpf_func_id_BPF_FUNC_redirect_map: bpf_func_id = 51;
pub const bpf_func_id_BPF_FUNC_sk_redirect_map: bpf_func_id = 52;
pub const bpf_func_id_BPF_FUNC_sock_map_update: bpf_func_id = 53;
pub const bpf_func_id_BPF_FUNC_xdp_adjust_meta: bpf_func_id = 54;
pub const bpf_func_id_BPF_FUNC_perf_event_read_value: bpf_func_id = 55;
pub const bpf_func_id_BPF_FUNC_perf_prog_read_value: bpf_func_id = 56;
pub const bpf_func_id_BPF_FUNC_getsockopt: bpf_func_id = 57;
pub const bpf_func_id_BPF_FUNC_override_return: bpf_func_id = 58;
pub const bpf_func_id_BPF_FUNC_sock_ops_cb_flags_set: bpf_func_id = 59;
pub const bpf_func_id_BPF_FUNC_msg_redirect_map: bpf_func_id = 60;
pub const bpf_func_id_BPF_FUNC_msg_apply_bytes: bpf_func_id = 61;
pub const bpf_func_id_BPF_FUNC_msg_cork_bytes: bpf_func_id = 62;
pub const bpf_func_id_BPF_FUNC_msg_pull_data: bpf_func_id = 63;
pub const bpf_func_id_BPF_FUNC_bind: bpf_func_id = 64;
pub const bpf_func_id_BPF_FUNC_xdp_adjust_tail: bpf_func_id = 65;
pub const bpf_func_id_BPF_FUNC_skb_get_xfrm_state: bpf_func_id = 66;
pub const bpf_func_id_BPF_FUNC_get_stack: bpf_func_id = 67;
pub const bpf_func_id_BPF_FUNC_skb_load_bytes_relative: bpf_func_id = 68;
pub const bpf_func_id_BPF_FUNC_fib_lookup: bpf_func_id = 69;
pub const bpf_func_id_BPF_FUNC_sock_hash_update: bpf_func_id = 70;
pub const bpf_func_id_BPF_FUNC_msg_redirect_hash: bpf_func_id = 71;
pub const bpf_func_id_BPF_FUNC_sk_redirect_hash: bpf_func_id = 72;
pub const bpf_func_id_BPF_FUNC_lwt_push_encap: bpf_func_id = 73;
pub const bpf_func_id_BPF_FUNC_lwt_seg6_store_bytes: bpf_func_id = 74;
pub const bpf_func_id_BPF_FUNC_lwt_seg6_adjust_srh: bpf_func_id = 75;
pub const bpf_func_id_BPF_FUNC_lwt_seg6_action: bpf_func_id = 76;
pub const bpf_func_id_BPF_FUNC_rc_repeat: bpf_func_id = 77;
pub const bpf_func_id_BPF_FUNC_rc_keydown: bpf_func_id = 78;
pub const bpf_func_id___BPF_FUNC_MAX_ID: bpf_func_id = 79;
pub type bpf_func_id = u32;
pub const bpf_adj_room_mode_BPF_ADJ_ROOM_NET: bpf_adj_room_mode = 0;
pub type bpf_adj_room_mode = u32;
pub const bpf_hdr_start_off_BPF_HDR_START_MAC: bpf_hdr_start_off = 0;
pub const bpf_hdr_start_off_BPF_HDR_START_NET: bpf_hdr_start_off = 1;
pub type bpf_hdr_start_off = u32;
pub const bpf_lwt_encap_mode_BPF_LWT_ENCAP_SEG6: bpf_lwt_encap_mode = 0;
pub const bpf_lwt_encap_mode_BPF_LWT_ENCAP_SEG6_INLINE: bpf_lwt_encap_mode = 1;
pub type bpf_lwt_encap_mode = u32;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_tunnel_key {
    pub tunnel_id: __u32,
    pub __bindgen_anon_1: bpf_tunnel_key__bindgen_ty_1,
    pub tunnel_tos: __u8,
    pub tunnel_ttl: __u8,
    pub tunnel_ext: __u16,
    pub tunnel_label: __u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_tunnel_key__bindgen_ty_1 {
    pub remote_ipv4: __u32,
    pub remote_ipv6: [__u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
}
#[test]
fn bindgen_test_layout_bpf_tunnel_key__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<bpf_tunnel_key__bindgen_ty_1>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_tunnel_key__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_tunnel_key__bindgen_ty_1>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_tunnel_key__bindgen_ty_1))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_tunnel_key__bindgen_ty_1>())).remote_ipv4 as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_tunnel_key__bindgen_ty_1),
            "::",
            stringify!(remote_ipv4)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_tunnel_key__bindgen_ty_1>())).remote_ipv6 as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_tunnel_key__bindgen_ty_1),
            "::",
            stringify!(remote_ipv6)
        )
    );
}
#[test]
fn bindgen_test_layout_bpf_tunnel_key() {
    assert_eq!(
        ::std::mem::size_of::<bpf_tunnel_key>(),
        28usize,
        concat!("Size of: ", stringify!(bpf_tunnel_key))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_tunnel_key>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_tunnel_key))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_tunnel_key>())).tunnel_id as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_tunnel_key),
            "::",
            stringify!(tunnel_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_tunnel_key>())).tunnel_tos as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_tunnel_key),
            "::",
            stringify!(tunnel_tos)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_tunnel_key>())).tunnel_ttl as *const _ as usize },
        21usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_tunnel_key),
            "::",
            stringify!(tunnel_ttl)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_tunnel_key>())).tunnel_ext as *const _ as usize },
        22usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_tunnel_key),
            "::",
            stringify!(tunnel_ext)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_tunnel_key>())).tunnel_label as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_tunnel_key),
            "::",
            stringify!(tunnel_label)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_xfrm_state {
    pub reqid: __u32,
    pub spi: __u32,
    pub family: __u16,
    pub __bindgen_anon_1: bpf_xfrm_state__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_xfrm_state__bindgen_ty_1 {
    pub remote_ipv4: __u32,
    pub remote_ipv6: [__u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
}
#[test]
fn bindgen_test_layout_bpf_xfrm_state__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<bpf_xfrm_state__bindgen_ty_1>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_xfrm_state__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_xfrm_state__bindgen_ty_1>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_xfrm_state__bindgen_ty_1))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_xfrm_state__bindgen_ty_1>())).remote_ipv4 as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_xfrm_state__bindgen_ty_1),
            "::",
            stringify!(remote_ipv4)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_xfrm_state__bindgen_ty_1>())).remote_ipv6 as *const _
                as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_xfrm_state__bindgen_ty_1),
            "::",
            stringify!(remote_ipv6)
        )
    );
}
#[test]
fn bindgen_test_layout_bpf_xfrm_state() {
    assert_eq!(
        ::std::mem::size_of::<bpf_xfrm_state>(),
        28usize,
        concat!("Size of: ", stringify!(bpf_xfrm_state))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_xfrm_state>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_xfrm_state))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_xfrm_state>())).reqid as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_xfrm_state),
            "::",
            stringify!(reqid)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_xfrm_state>())).spi as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_xfrm_state),
            "::",
            stringify!(spi)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_xfrm_state>())).family as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_xfrm_state),
            "::",
            stringify!(family)
        )
    );
}
pub const bpf_ret_code_BPF_OK: bpf_ret_code = 0;
pub const bpf_ret_code_BPF_DROP: bpf_ret_code = 2;
pub const bpf_ret_code_BPF_REDIRECT: bpf_ret_code = 7;
pub type bpf_ret_code = u32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_sock {
    pub bound_dev_if: __u32,
    pub family: __u32,
    pub type_: __u32,
    pub protocol: __u32,
    pub mark: __u32,
    pub priority: __u32,
    pub src_ip4: __u32,
    pub src_ip6: [__u32; 4usize],
    pub src_port: __u32,
}
#[test]
fn bindgen_test_layout_bpf_sock() {
    assert_eq!(
        ::std::mem::size_of::<bpf_sock>(),
        48usize,
        concat!("Size of: ", stringify!(bpf_sock))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_sock>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_sock))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock>())).bound_dev_if as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock),
            "::",
            stringify!(bound_dev_if)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock>())).family as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock),
            "::",
            stringify!(family)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock>())).type_ as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock>())).protocol as *const _ as usize },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock),
            "::",
            stringify!(protocol)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock>())).mark as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock),
            "::",
            stringify!(mark)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock>())).priority as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock),
            "::",
            stringify!(priority)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock>())).src_ip4 as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock),
            "::",
            stringify!(src_ip4)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock>())).src_ip6 as *const _ as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock),
            "::",
            stringify!(src_ip6)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock>())).src_port as *const _ as usize },
        44usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock),
            "::",
            stringify!(src_port)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_prog_info {
    pub type_: __u32,
    pub id: __u32,
    pub tag: [__u8; 8usize],
    pub jited_prog_len: __u32,
    pub xlated_prog_len: __u32,
    pub jited_prog_insns: __u64,
    pub xlated_prog_insns: __u64,
    pub load_time: __u64,
    pub created_by_uid: __u32,
    pub nr_map_ids: __u32,
    pub map_ids: __u64,
    pub name: [::std::os::raw::c_char; 16usize],
    pub ifindex: __u32,
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize], u8>,
    pub netns_dev: __u64,
    pub netns_ino: __u64,
    pub nr_jited_ksyms: __u32,
    pub nr_jited_func_lens: __u32,
    pub jited_ksyms: __u64,
    pub jited_func_lens: __u64,
}
#[test]
fn bindgen_test_layout_bpf_prog_info() {
    assert_eq!(
        ::std::mem::size_of::<bpf_prog_info>(),
        128usize,
        concat!("Size of: ", stringify!(bpf_prog_info))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_prog_info>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_prog_info))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).id as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).tag as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(tag)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).jited_prog_len as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(jited_prog_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).xlated_prog_len as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(xlated_prog_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).jited_prog_insns as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(jited_prog_insns)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).xlated_prog_insns as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(xlated_prog_insns)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).load_time as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(load_time)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).created_by_uid as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(created_by_uid)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).nr_map_ids as *const _ as usize },
        52usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(nr_map_ids)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).map_ids as *const _ as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(map_ids)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).name as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(name)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).ifindex as *const _ as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(ifindex)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).netns_dev as *const _ as usize },
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(netns_dev)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).netns_ino as *const _ as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(netns_ino)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).nr_jited_ksyms as *const _ as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(nr_jited_ksyms)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_prog_info>())).nr_jited_func_lens as *const _ as usize
        },
        108usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(nr_jited_func_lens)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).jited_ksyms as *const _ as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(jited_ksyms)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_prog_info>())).jited_func_lens as *const _ as usize },
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_prog_info),
            "::",
            stringify!(jited_func_lens)
        )
    );
}
impl bpf_prog_info {
    #[inline]
    pub fn gpl_compatible(&self) -> __u32 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_gpl_compatible(&mut self, val: __u32) {
        unsafe {
            let val: u32 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 1u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(gpl_compatible: __u32) -> __BindgenBitfieldUnit<[u8; 1usize], u8> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 1usize], u8> =
            Default::default();
        __bindgen_bitfield_unit.set(0usize, 1u8, {
            let gpl_compatible: u32 = unsafe { ::std::mem::transmute(gpl_compatible) };
            gpl_compatible as u64
        });
        __bindgen_bitfield_unit
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_map_info {
    pub type_: __u32,
    pub id: __u32,
    pub key_size: __u32,
    pub value_size: __u32,
    pub max_entries: __u32,
    pub map_flags: __u32,
    pub name: [::std::os::raw::c_char; 16usize],
    pub ifindex: __u32,
    pub netns_dev: __u64,
    pub netns_ino: __u64,
    pub btf_id: __u32,
    pub btf_key_type_id: __u32,
    pub btf_value_type_id: __u32,
}
#[test]
fn bindgen_test_layout_bpf_map_info() {
    assert_eq!(
        ::std::mem::size_of::<bpf_map_info>(),
        80usize,
        concat!("Size of: ", stringify!(bpf_map_info))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_map_info>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_map_info))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).id as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).key_size as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(key_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).value_size as *const _ as usize },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(value_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).max_entries as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(max_entries)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).map_flags as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(map_flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).name as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(name)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).ifindex as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(ifindex)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).netns_dev as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(netns_dev)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).netns_ino as *const _ as usize },
        56usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(netns_ino)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).btf_id as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(btf_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).btf_key_type_id as *const _ as usize },
        68usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(btf_key_type_id)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_map_info>())).btf_value_type_id as *const _ as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_map_info),
            "::",
            stringify!(btf_value_type_id)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_btf_info {
    pub btf: __u64,
    pub btf_size: __u32,
    pub id: __u32,
}
#[test]
fn bindgen_test_layout_bpf_btf_info() {
    assert_eq!(
        ::std::mem::size_of::<bpf_btf_info>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_btf_info))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_btf_info>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_btf_info))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_btf_info>())).btf as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_btf_info),
            "::",
            stringify!(btf)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_btf_info>())).btf_size as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_btf_info),
            "::",
            stringify!(btf_size)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_btf_info>())).id as *const _ as usize },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_btf_info),
            "::",
            stringify!(id)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_sock_addr {
    pub user_family: __u32,
    pub user_ip4: __u32,
    pub user_ip6: [__u32; 4usize],
    pub user_port: __u32,
    pub family: __u32,
    pub type_: __u32,
    pub protocol: __u32,
    pub msg_src_ip4: __u32,
    pub msg_src_ip6: [__u32; 4usize],
}
#[test]
fn bindgen_test_layout_bpf_sock_addr() {
    assert_eq!(
        ::std::mem::size_of::<bpf_sock_addr>(),
        60usize,
        concat!("Size of: ", stringify!(bpf_sock_addr))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_sock_addr>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_sock_addr))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_addr>())).user_family as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_addr),
            "::",
            stringify!(user_family)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_addr>())).user_ip4 as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_addr),
            "::",
            stringify!(user_ip4)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_addr>())).user_ip6 as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_addr),
            "::",
            stringify!(user_ip6)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_addr>())).user_port as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_addr),
            "::",
            stringify!(user_port)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_addr>())).family as *const _ as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_addr),
            "::",
            stringify!(family)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_addr>())).type_ as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_addr),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_addr>())).protocol as *const _ as usize },
        36usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_addr),
            "::",
            stringify!(protocol)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_addr>())).msg_src_ip4 as *const _ as usize },
        40usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_addr),
            "::",
            stringify!(msg_src_ip4)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_addr>())).msg_src_ip6 as *const _ as usize },
        44usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_addr),
            "::",
            stringify!(msg_src_ip6)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_sock_ops {
    pub op: __u32,
    pub __bindgen_anon_1: bpf_sock_ops__bindgen_ty_1,
    pub family: __u32,
    pub remote_ip4: __u32,
    pub local_ip4: __u32,
    pub remote_ip6: [__u32; 4usize],
    pub local_ip6: [__u32; 4usize],
    pub remote_port: __u32,
    pub local_port: __u32,
    pub is_fullsock: __u32,
    pub snd_cwnd: __u32,
    pub srtt_us: __u32,
    pub bpf_sock_ops_cb_flags: __u32,
    pub state: __u32,
    pub rtt_min: __u32,
    pub snd_ssthresh: __u32,
    pub rcv_nxt: __u32,
    pub snd_nxt: __u32,
    pub snd_una: __u32,
    pub mss_cache: __u32,
    pub ecn_flags: __u32,
    pub rate_delivered: __u32,
    pub rate_interval_us: __u32,
    pub packets_out: __u32,
    pub retrans_out: __u32,
    pub total_retrans: __u32,
    pub segs_in: __u32,
    pub data_segs_in: __u32,
    pub segs_out: __u32,
    pub data_segs_out: __u32,
    pub lost_out: __u32,
    pub sacked_out: __u32,
    pub sk_txhash: __u32,
    pub bytes_received: __u64,
    pub bytes_acked: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_sock_ops__bindgen_ty_1 {
    pub args: [__u32; 4usize],
    pub reply: __u32,
    pub replylong: [__u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
}
#[test]
fn bindgen_test_layout_bpf_sock_ops__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<bpf_sock_ops__bindgen_ty_1>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_sock_ops__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_sock_ops__bindgen_ty_1>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_sock_ops__bindgen_ty_1))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops__bindgen_ty_1>())).args as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops__bindgen_ty_1),
            "::",
            stringify!(args)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_sock_ops__bindgen_ty_1>())).reply as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops__bindgen_ty_1),
            "::",
            stringify!(reply)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_sock_ops__bindgen_ty_1>())).replylong as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops__bindgen_ty_1),
            "::",
            stringify!(replylong)
        )
    );
}
#[test]
fn bindgen_test_layout_bpf_sock_ops() {
    assert_eq!(
        ::std::mem::size_of::<bpf_sock_ops>(),
        184usize,
        concat!("Size of: ", stringify!(bpf_sock_ops))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_sock_ops>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_sock_ops))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).op as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(op)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).family as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(family)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).remote_ip4 as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(remote_ip4)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).local_ip4 as *const _ as usize },
        28usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(local_ip4)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).remote_ip6 as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(remote_ip6)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).local_ip6 as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(local_ip6)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).remote_port as *const _ as usize },
        64usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(remote_port)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).local_port as *const _ as usize },
        68usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(local_port)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).is_fullsock as *const _ as usize },
        72usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(is_fullsock)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).snd_cwnd as *const _ as usize },
        76usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(snd_cwnd)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).srtt_us as *const _ as usize },
        80usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(srtt_us)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_sock_ops>())).bpf_sock_ops_cb_flags as *const _ as usize
        },
        84usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(bpf_sock_ops_cb_flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).state as *const _ as usize },
        88usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(state)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).rtt_min as *const _ as usize },
        92usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(rtt_min)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).snd_ssthresh as *const _ as usize },
        96usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(snd_ssthresh)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).rcv_nxt as *const _ as usize },
        100usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(rcv_nxt)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).snd_nxt as *const _ as usize },
        104usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(snd_nxt)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).snd_una as *const _ as usize },
        108usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(snd_una)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).mss_cache as *const _ as usize },
        112usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(mss_cache)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).ecn_flags as *const _ as usize },
        116usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(ecn_flags)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).rate_delivered as *const _ as usize },
        120usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(rate_delivered)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).rate_interval_us as *const _ as usize },
        124usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(rate_interval_us)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).packets_out as *const _ as usize },
        128usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(packets_out)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).retrans_out as *const _ as usize },
        132usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(retrans_out)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).total_retrans as *const _ as usize },
        136usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(total_retrans)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).segs_in as *const _ as usize },
        140usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(segs_in)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).data_segs_in as *const _ as usize },
        144usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(data_segs_in)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).segs_out as *const _ as usize },
        148usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(segs_out)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).data_segs_out as *const _ as usize },
        152usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(data_segs_out)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).lost_out as *const _ as usize },
        156usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(lost_out)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).sacked_out as *const _ as usize },
        160usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(sacked_out)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).sk_txhash as *const _ as usize },
        164usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(sk_txhash)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).bytes_received as *const _ as usize },
        168usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(bytes_received)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_sock_ops>())).bytes_acked as *const _ as usize },
        176usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_sock_ops),
            "::",
            stringify!(bytes_acked)
        )
    );
}
pub const BPF_SOCK_OPS_VOID: _bindgen_ty_3 = 0;
pub const BPF_SOCK_OPS_TIMEOUT_INIT: _bindgen_ty_3 = 1;
pub const BPF_SOCK_OPS_RWND_INIT: _bindgen_ty_3 = 2;
pub const BPF_SOCK_OPS_TCP_CONNECT_CB: _bindgen_ty_3 = 3;
pub const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: _bindgen_ty_3 = 4;
pub const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: _bindgen_ty_3 = 5;
pub const BPF_SOCK_OPS_NEEDS_ECN: _bindgen_ty_3 = 6;
pub const BPF_SOCK_OPS_BASE_RTT: _bindgen_ty_3 = 7;
pub const BPF_SOCK_OPS_RTO_CB: _bindgen_ty_3 = 8;
pub const BPF_SOCK_OPS_RETRANS_CB: _bindgen_ty_3 = 9;
pub const BPF_SOCK_OPS_STATE_CB: _bindgen_ty_3 = 10;
pub type _bindgen_ty_3 = u32;
pub const BPF_TCP_ESTABLISHED: _bindgen_ty_4 = 1;
pub const BPF_TCP_SYN_SENT: _bindgen_ty_4 = 2;
pub const BPF_TCP_SYN_RECV: _bindgen_ty_4 = 3;
pub const BPF_TCP_FIN_WAIT1: _bindgen_ty_4 = 4;
pub const BPF_TCP_FIN_WAIT2: _bindgen_ty_4 = 5;
pub const BPF_TCP_TIME_WAIT: _bindgen_ty_4 = 6;
pub const BPF_TCP_CLOSE: _bindgen_ty_4 = 7;
pub const BPF_TCP_CLOSE_WAIT: _bindgen_ty_4 = 8;
pub const BPF_TCP_LAST_ACK: _bindgen_ty_4 = 9;
pub const BPF_TCP_LISTEN: _bindgen_ty_4 = 10;
pub const BPF_TCP_CLOSING: _bindgen_ty_4 = 11;
pub const BPF_TCP_NEW_SYN_RECV: _bindgen_ty_4 = 12;
pub const BPF_TCP_MAX_STATES: _bindgen_ty_4 = 13;
pub type _bindgen_ty_4 = u32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_perf_event_value {
    pub counter: __u64,
    pub enabled: __u64,
    pub running: __u64,
}
#[test]
fn bindgen_test_layout_bpf_perf_event_value() {
    assert_eq!(
        ::std::mem::size_of::<bpf_perf_event_value>(),
        24usize,
        concat!("Size of: ", stringify!(bpf_perf_event_value))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_perf_event_value>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_perf_event_value))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_perf_event_value>())).counter as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_perf_event_value),
            "::",
            stringify!(counter)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_perf_event_value>())).enabled as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_perf_event_value),
            "::",
            stringify!(enabled)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_perf_event_value>())).running as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_perf_event_value),
            "::",
            stringify!(running)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_cgroup_dev_ctx {
    pub access_type: __u32,
    pub major: __u32,
    pub minor: __u32,
}
#[test]
fn bindgen_test_layout_bpf_cgroup_dev_ctx() {
    assert_eq!(
        ::std::mem::size_of::<bpf_cgroup_dev_ctx>(),
        12usize,
        concat!("Size of: ", stringify!(bpf_cgroup_dev_ctx))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_cgroup_dev_ctx>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_cgroup_dev_ctx))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_cgroup_dev_ctx>())).access_type as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_cgroup_dev_ctx),
            "::",
            stringify!(access_type)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_cgroup_dev_ctx>())).major as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_cgroup_dev_ctx),
            "::",
            stringify!(major)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_cgroup_dev_ctx>())).minor as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_cgroup_dev_ctx),
            "::",
            stringify!(minor)
        )
    );
}
#[repr(C)]
#[derive(Debug)]
pub struct bpf_raw_tracepoint_args {
    pub args: __IncompleteArrayField<__u64>,
}
#[test]
fn bindgen_test_layout_bpf_raw_tracepoint_args() {
    assert_eq!(
        ::std::mem::size_of::<bpf_raw_tracepoint_args>(),
        0usize,
        concat!("Size of: ", stringify!(bpf_raw_tracepoint_args))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_raw_tracepoint_args>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_raw_tracepoint_args))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_raw_tracepoint_args>())).args as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_raw_tracepoint_args),
            "::",
            stringify!(args)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_fib_lookup {
    pub family: __u8,
    pub l4_protocol: __u8,
    pub sport: __be16,
    pub dport: __be16,
    pub tot_len: __u16,
    pub ifindex: __u32,
    pub __bindgen_anon_1: bpf_fib_lookup__bindgen_ty_1,
    pub __bindgen_anon_2: bpf_fib_lookup__bindgen_ty_2,
    pub __bindgen_anon_3: bpf_fib_lookup__bindgen_ty_3,
    pub h_vlan_proto: __be16,
    pub h_vlan_TCI: __be16,
    pub smac: [__u8; 6usize],
    pub dmac: [__u8; 6usize],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_1 {
    pub tos: __u8,
    pub flowlabel: __be32,
    pub rt_metric: __u32,
    _bindgen_union_align: u32,
}
#[test]
fn bindgen_test_layout_bpf_fib_lookup__bindgen_ty_1() {
    assert_eq!(
        ::std::mem::size_of::<bpf_fib_lookup__bindgen_ty_1>(),
        4usize,
        concat!("Size of: ", stringify!(bpf_fib_lookup__bindgen_ty_1))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_fib_lookup__bindgen_ty_1>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_fib_lookup__bindgen_ty_1))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_fib_lookup__bindgen_ty_1>())).tos as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup__bindgen_ty_1),
            "::",
            stringify!(tos)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_fib_lookup__bindgen_ty_1>())).flowlabel as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup__bindgen_ty_1),
            "::",
            stringify!(flowlabel)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_fib_lookup__bindgen_ty_1>())).rt_metric as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup__bindgen_ty_1),
            "::",
            stringify!(rt_metric)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_2 {
    pub ipv4_src: __be32,
    pub ipv6_src: [__u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
}
#[test]
fn bindgen_test_layout_bpf_fib_lookup__bindgen_ty_2() {
    assert_eq!(
        ::std::mem::size_of::<bpf_fib_lookup__bindgen_ty_2>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_fib_lookup__bindgen_ty_2))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_fib_lookup__bindgen_ty_2>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_fib_lookup__bindgen_ty_2))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_fib_lookup__bindgen_ty_2>())).ipv4_src as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup__bindgen_ty_2),
            "::",
            stringify!(ipv4_src)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_fib_lookup__bindgen_ty_2>())).ipv6_src as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup__bindgen_ty_2),
            "::",
            stringify!(ipv6_src)
        )
    );
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_fib_lookup__bindgen_ty_3 {
    pub ipv4_dst: __be32,
    pub ipv6_dst: [__u32; 4usize],
    _bindgen_union_align: [u32; 4usize],
}
#[test]
fn bindgen_test_layout_bpf_fib_lookup__bindgen_ty_3() {
    assert_eq!(
        ::std::mem::size_of::<bpf_fib_lookup__bindgen_ty_3>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_fib_lookup__bindgen_ty_3))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_fib_lookup__bindgen_ty_3>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_fib_lookup__bindgen_ty_3))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_fib_lookup__bindgen_ty_3>())).ipv4_dst as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup__bindgen_ty_3),
            "::",
            stringify!(ipv4_dst)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<bpf_fib_lookup__bindgen_ty_3>())).ipv6_dst as *const _ as usize
        },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup__bindgen_ty_3),
            "::",
            stringify!(ipv6_dst)
        )
    );
}
#[test]
fn bindgen_test_layout_bpf_fib_lookup() {
    assert_eq!(
        ::std::mem::size_of::<bpf_fib_lookup>(),
        64usize,
        concat!("Size of: ", stringify!(bpf_fib_lookup))
    );
    assert_eq!(
        ::std::mem::align_of::<bpf_fib_lookup>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_fib_lookup))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).family as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(family)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).l4_protocol as *const _ as usize },
        1usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(l4_protocol)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).sport as *const _ as usize },
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(sport)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).dport as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(dport)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).tot_len as *const _ as usize },
        6usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(tot_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).ifindex as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(ifindex)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).h_vlan_proto as *const _ as usize },
        48usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(h_vlan_proto)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).h_vlan_TCI as *const _ as usize },
        50usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(h_vlan_TCI)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).smac as *const _ as usize },
        52usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(smac)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<bpf_fib_lookup>())).dmac as *const _ as usize },
        58usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_fib_lookup),
            "::",
            stringify!(dmac)
        )
    );
}
pub const bpf_task_fd_type_BPF_FD_TYPE_RAW_TRACEPOINT: bpf_task_fd_type = 0;
pub const bpf_task_fd_type_BPF_FD_TYPE_TRACEPOINT: bpf_task_fd_type = 1;
pub const bpf_task_fd_type_BPF_FD_TYPE_KPROBE: bpf_task_fd_type = 2;
pub const bpf_task_fd_type_BPF_FD_TYPE_KRETPROBE: bpf_task_fd_type = 3;
pub const bpf_task_fd_type_BPF_FD_TYPE_UPROBE: bpf_task_fd_type = 4;
pub const bpf_task_fd_type_BPF_FD_TYPE_URETPROBE: bpf_task_fd_type = 5;
pub type bpf_task_fd_type = u32;
pub const bpf_probe_attach_type_BPF_PROBE_ENTRY: bpf_probe_attach_type = 0;
pub const bpf_probe_attach_type_BPF_PROBE_RETURN: bpf_probe_attach_type = 1;
pub type bpf_probe_attach_type = u32;
extern "C" {
    pub fn bpf_create_map(
        map_type: bpf_map_type,
        name: *const ::std::os::raw::c_char,
        key_size: ::std::os::raw::c_int,
        value_size: ::std::os::raw::c_int,
        max_entries: ::std::os::raw::c_int,
        map_flags: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_update_elem(
        fd: ::std::os::raw::c_int,
        key: *mut ::std::os::raw::c_void,
        value: *mut ::std::os::raw::c_void,
        flags: ::std::os::raw::c_ulonglong,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_lookup_elem(
        fd: ::std::os::raw::c_int,
        key: *mut ::std::os::raw::c_void,
        value: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_delete_elem(
        fd: ::std::os::raw::c_int,
        key: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_get_first_key(
        fd: ::std::os::raw::c_int,
        key: *mut ::std::os::raw::c_void,
        key_size: usize,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_get_next_key(
        fd: ::std::os::raw::c_int,
        key: *mut ::std::os::raw::c_void,
        next_key: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_prog_load(
        prog_type: bpf_prog_type,
        name: *const ::std::os::raw::c_char,
        insns: *const bpf_insn,
        insn_len: ::std::os::raw::c_int,
        license: *const ::std::os::raw::c_char,
        kern_version: ::std::os::raw::c_uint,
        log_level: ::std::os::raw::c_int,
        log_buf: *mut ::std::os::raw::c_char,
        log_buf_size: ::std::os::raw::c_uint,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_attach_socket(
        sockfd: ::std::os::raw::c_int,
        progfd: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_open_raw_sock(name: *const ::std::os::raw::c_char) -> ::std::os::raw::c_int;
}
pub type perf_reader_raw_cb = ::std::option::Option<
    unsafe extern "C" fn(
        cb_cookie: *mut ::std::os::raw::c_void,
        raw: *mut ::std::os::raw::c_void,
        raw_size: ::std::os::raw::c_int,
    ),
>;
pub type perf_reader_lost_cb =
    ::std::option::Option<unsafe extern "C" fn(cb_cookie: *mut ::std::os::raw::c_void, lost: u64)>;
extern "C" {
    pub fn bpf_attach_kprobe(
        progfd: ::std::os::raw::c_int,
        attach_type: bpf_probe_attach_type,
        ev_name: *const ::std::os::raw::c_char,
        fn_name: *const ::std::os::raw::c_char,
        fn_offset: u64,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_detach_kprobe(ev_name: *const ::std::os::raw::c_char) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_attach_uprobe(
        progfd: ::std::os::raw::c_int,
        attach_type: bpf_probe_attach_type,
        ev_name: *const ::std::os::raw::c_char,
        binary_path: *const ::std::os::raw::c_char,
        offset: u64,
        pid: pid_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_detach_uprobe(ev_name: *const ::std::os::raw::c_char) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_attach_tracepoint(
        progfd: ::std::os::raw::c_int,
        tp_category: *const ::std::os::raw::c_char,
        tp_name: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_detach_tracepoint(
        tp_category: *const ::std::os::raw::c_char,
        tp_name: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_attach_raw_tracepoint(
        progfd: ::std::os::raw::c_int,
        tp_name: *mut ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_open_perf_buffer(
        raw_cb: perf_reader_raw_cb,
        lost_cb: perf_reader_lost_cb,
        cb_cookie: *mut ::std::os::raw::c_void,
        pid: ::std::os::raw::c_int,
        cpu: ::std::os::raw::c_int,
        page_cnt: ::std::os::raw::c_int,
    ) -> *mut ::std::os::raw::c_void;
}
extern "C" {
    pub fn bpf_attach_xdp(
        dev_name: *const ::std::os::raw::c_char,
        progfd: ::std::os::raw::c_int,
        flags: u32,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_attach_perf_event_raw(
        progfd: ::std::os::raw::c_int,
        perf_event_attr: *mut ::std::os::raw::c_void,
        pid: pid_t,
        cpu: ::std::os::raw::c_int,
        group_fd: ::std::os::raw::c_int,
        extra_flags: ::std::os::raw::c_ulong,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_attach_perf_event(
        progfd: ::std::os::raw::c_int,
        ev_type: u32,
        ev_config: u32,
        sample_period: u64,
        sample_freq: u64,
        pid: pid_t,
        cpu: ::std::os::raw::c_int,
        group_fd: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_open_perf_event(
        type_: u32,
        config: u64,
        pid: ::std::os::raw::c_int,
        cpu: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_close_perf_event_fd(fd: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_obj_pin(
        fd: ::std::os::raw::c_int,
        pathname: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_obj_get(pathname: *const ::std::os::raw::c_char) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_obj_get_info(
        prog_map_fd: ::std::os::raw::c_int,
        info: *mut ::std::os::raw::c_void,
        info_len: *mut u32,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_prog_compute_tag(
        insns: *const bpf_insn,
        prog_len: ::std::os::raw::c_int,
        tag: *mut ::std::os::raw::c_ulonglong,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_prog_get_tag(
        fd: ::std::os::raw::c_int,
        tag: *mut ::std::os::raw::c_ulonglong,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_prog_get_next_id(start_id: u32, next_id: *mut u32) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_prog_get_fd_by_id(id: u32) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn bpf_map_get_fd_by_id(id: u32) -> ::std::os::raw::c_int;
}
