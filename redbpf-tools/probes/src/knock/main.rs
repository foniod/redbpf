// Copyright 2019-2020 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#![no_std]
#![no_main]
use probes::knock::{Connection, Knock, KnockAttempt, PortSequence, MAX_SEQ_LEN};
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

const TCP_FLAG_SYN: u16 = 0x0002u16.to_be();

#[map]
static mut sequence: HashMap<u8, PortSequence> = HashMap::with_max_entries(1);

#[map]
static mut knocks: HashMap<u32, Knock> = HashMap::with_max_entries(1024);

#[map]
static mut knock_attempts: PerfMap<KnockAttempt> = PerfMap::with_max_entries(1024);

#[map]
static mut connections: PerfMap<Connection> = PerfMap::with_max_entries(1024);

#[xdp("knock")]
pub fn probe(ctx: XdpContext) -> XdpResult {
    // only process TCP packets
    let tcp = match ctx.transport()? {
        t @ Transport::TCP(_) => t,
        _ => return Ok(XdpAction::Pass),
    };
    let ip = unsafe { *ctx.ip()? };

    // get the knock sequence as configured by user space
    let target_seq = unsafe {
        let seq_id = 0u8;
        sequence.get_mut(&seq_id).ok_or(NetworkError::Other)?
    };

    // we only process SYN packets, all other packets can go through
    if !has_flag(&tcp, TCP_FLAG_SYN) {
        return Ok(XdpAction::Pass);
    }

    // get the knock data for the source IP address
    let mut knock = unsafe {
        let key = ip.saddr;
        match knocks.get_mut(&key) {
            Some(k) => k,
            None => {
                let knock = Knock::new(target_seq.target);
                knocks.set(&key, &knock);
                knocks.get_mut(&key).ok_or(NetworkError::Other)?
            }
        }
    };

    // this peer has already completed the knock sequence so data can pass
    if knock.complete == 1 {
        return Ok(XdpAction::Pass);
    }

    if tcp.dest() == target_seq.target as u16 {
        // block a connection attempt to the target port if the knock sequence
        // is incomplete
        if !target_seq.is_complete(&knock.sequence) {
            // notify user space that we're blocking the connection
            let conn = Connection {
                source_ip: u32::from_be(ip.saddr),
                allowed: 0,
            };
            unsafe { connections.insert(&ctx, &MapData::new(conn)) }

            return Ok(XdpAction::Drop);
        }

        // mark the knock as complete, so that for successive connections we
        // exit a bit earlier and we only notify user space once.
        knock.complete = 1;

        // notify user space that we're allowing the connection
        let conn = Connection {
            source_ip: u32::from_be(ip.saddr),
            allowed: 1,
        };
        unsafe { connections.insert(&ctx, &MapData::new(conn)) }

        return Ok(XdpAction::Pass);
    }

    // this is a SYN packet directed to a port that is not the target port,
    // so process it as a knock attempt.

    // restart wrong knock sequences once they reach the target sequence length.
    // The verifier needs to know that there's an upper bound to
    // knock.sequence.len so we check for both target_seq.len and MAX_SEQ_LEN
    if knock.sequence.len >= target_seq.len || knock.sequence.len >= MAX_SEQ_LEN {
        knock.sequence.len = 0;
    }
    knock.sequence.ports[knock.sequence.len] = tcp.dest();
    knock.sequence.len += 1;

    // notify user space that ip.saddr knocked on tcp.dest()
    let attempt = KnockAttempt {
        source_ip: u32::from_be(ip.saddr),
        padding: 0,
        sequence: knock.sequence.clone(),
    };
    unsafe { knock_attempts.insert(&ctx, &MapData::new(attempt)) }

    return Ok(XdpAction::Pass);
}

#[inline]
fn has_flag(tcp: &Transport, flag: u16) -> bool {
    if let Transport::TCP(hdr) = tcp {
        let flags = unsafe { *(&(**hdr)._bitfield_1 as *const _ as *const u16) };
        return flags & flag != 0;
    }

    return false;
}
