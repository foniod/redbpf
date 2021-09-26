use bpf_sys::headers::prefix_kernel_headers;
use lazy_static::lazy_static;

#[cfg(target_arch = "x86_64")]
pub(crate) const KERNEL_HEADERS: [&str; 7] = [
    "arch/x86/include",
    "arch/x86/include/generated",
    "include",
    "include/generated",
    "arch/include/generated/uapi",
    "arch/x86/include/uapi",
    "include/uapi",
];

#[cfg(target_arch = "aarch64")]
pub(crate) const KERNEL_HEADERS: [&str; 8] = [
    "arch/arm64/include",
    "arch/arm64/include/generated",
    "include",
    "include/generated",
    "arch/include/generated/uapi",
    "arch/arm64/include/uapi",
    "arch/arm64/include/generated/uapi",
    "include/uapi",
];

lazy_static! {
    pub(crate) static ref BUILD_FLAGS: Vec<&'static str> = {
        let mut flags = vec![
            "-D__BPF_TRACING__",
            "-D__KERNEL__",
            "-Wall",
            "-Werror",
            "-Wunused",
            "-Wno-unknown-warning-option",
            "-Wno-frame-address",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
            "-Wno-unused-parameter",
            "-Wno-missing-field-initializers",
            "-Wno-initializer-overrides",
            "-Wno-unknown-pragmas",
            "-fno-stack-protector",
            "-Wno-unused-label",
            "-Wno-unused-variable",
            "-Wno-unused-function",
            "-Wno-address-of-packed-member",
            "-Wno-gnu-variable-sized-type-not-at-end",
        ];

        if cfg!(x86_64) {
            flags.push("-D__ASM_SYSREG_H");
        } else if cfg!(aarch64) {
            flags.push("-target");
            flags.push("aarch64");
        }

        flags
    };
}

pub(crate) fn kernel_headers() -> Result<Vec<String>, ()> {
    prefix_kernel_headers(&KERNEL_HEADERS).ok_or(())
}
