// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::CommandError;

use hexdump::hexdump;
use redbpf::load::Loader;
use redbpf::xdp;
use std::path::PathBuf;
use futures::stream::StreamExt;
use tokio;
use tokio::runtime::Runtime;
use tokio::signal;

pub fn load(program: &PathBuf, interface: Option<&str>) -> Result<(), CommandError> {
    let mut runtime = Runtime::new().unwrap();
    let _ = runtime.block_on(async {
        let mut loader = Loader::new()
            .xdp(interface.map(String::from), xdp::Flags::default())
            .load_file(&program)
            .await
            .expect("error loading file");
        tokio::spawn(async move {
            while let Some((name, events)) = loader.events.next().await {
                for event in events {
                    println!("-- Event: {} --", name);
                    hexdump(&event);
                }
            }
        });

        signal::ctrl_c().await
    });

    println!("exiting");

    Ok(())
}
