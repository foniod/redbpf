// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fs::read;
use std::io::Error;
use std::str::FromStr;

const SYS_CPU_ONLINE: &str = "/sys/devices/system/cpu/online";
const SYS_CPU_POSSIBLE: &str = "/sys/devices/system/cpu/possible";

pub type CpuId = i32;

/// Returns a list of online CPU IDs.
///
/// Error handling in this function is deliberately crashy
/// If the kernel returns with invalid data, it's OK to crash
/// If the kernel returns with different data format, it's OK to crash
/// If the user is trying to feed us invalid data, it's OK to crash
///
/// The only time an error is reported is when
/// `/sys/devices/system/cpu/online` can't be opened.
pub fn get_online() -> Result<Vec<CpuId>, Error> {
    let cpus = unsafe { String::from_utf8_unchecked(read(SYS_CPU_ONLINE)?) };
    Ok(list_from_string(&cpus.trim()))
}

/// Returns a list of possible CPU IDs.
///
/// Possible CPUs are fixed at boot time.
/// cf.,<https://elixir.bootlin.com/linux/v5.8/source/include/linux/cpumask.h#L50>
pub fn get_possible() -> Result<Vec<CpuId>, Error> {
    let cpus = unsafe {
        String::from_utf8_unchecked(
            read(SYS_CPU_POSSIBLE).expect("error figuring out possible cpus"),
        )
    };
    Ok(list_from_string(&cpus.trim()))
}

/// Returns the number of possible CPUs.
///
/// The number of possible CPUs is static after it is set during boot time
/// discovery phase.
/// For reference, see comments in kernel source: <https://elixir.bootlin.com/linux/v5.8/source/arch/x86/kernel/smpboot.c#L1447>
pub fn get_possible_num() -> usize {
    // get_possible() always returns Ok
    get_possible().unwrap().len()
}

fn list_from_string(cpus: &str) -> Vec<CpuId> {
    let cpu_list = cpus.split(',').flat_map(|group| {
        let mut split = group.split('-');
        let start = split.next();
        let end = split.next();

        if let (Some(start), None) = (start, end) {
            let cpuid = CpuId::from_str(start).unwrap();
            return cpuid..=cpuid;
        }

        let start = CpuId::from_str(start.unwrap()).unwrap();
        let end = CpuId::from_str(end.unwrap()).unwrap();
        start..=end
    });
    cpu_list.collect()
}

mod test {
    #[test]
    fn test() {
        use crate::cpus::list_from_string;
        assert_eq!(list_from_string("0"), vec![0]);
        assert_eq!(list_from_string("0-4"), vec![0, 1, 2, 3, 4]);
        assert_eq!(list_from_string("0-2,5-6"), vec![0, 1, 2, 5, 6]);
    }
}
