#![no_std]
// bindings module is used only for compiling BPF programs (= probes).
// And the compilation of BPF programs is executed by cargo-bpf on behalf of
// example-userspace.
//
// This source code is subject to be compiled twice during building example
// programs.
// - Once for building BPF programs by a cargo-bpf executed by a build-script
//   of example-userspace
// - Once for compiling modules of probes by a normal cargo
#[cfg(feature = "probes")]
pub mod bindings;

pub mod echo;
pub mod hashmaps;
pub mod mallocstacks;
pub mod p0f;
pub mod tasks;
pub mod tcp_lifetime;
pub mod vfsreadlat;
