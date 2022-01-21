#![no_std]
#![no_main]

use redbpf_probes::{bindings::iphdr, bindings::tcphdr, net::Transport, xdp::prelude::*};

use example_probes::p0f::{
    self, Quirks, TcpOptionMss, TcpOptionSackok, TcpOptionU32, TcpOptionWscale, TcpSignature,
};

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/log_events")]
static mut log_events: PerfMap<usize> = PerfMap::with_max_entries(512);

#[map(link_section = "maps/tcp_signatures")]
static mut tcp_signatures: PerfMap<TcpSignature> = PerfMap::with_max_entries(512);

// #[inline(always)]
#[inline(never)]
fn parse_tcp_signature(ctx: &XdpContext, tcp_header: &tcphdr, tcp_sig: &mut TcpSignature) -> bool {
    tcp_sig.set_quirk(Quirks::ZERO_SEQ, tcp_header.seq == 0);

    if tcp_header.ack() != 0 {
        tcp_sig.set_quirk(Quirks::ZERO_ACK, tcp_header.ack_seq == 0);
    } else {
        tcp_sig.set_quirk(Quirks::NZ_ACK, tcp_header.ack_seq != 0);
    }

    if tcp_header.urg() != 0 {
        tcp_sig.set_quirk_true(Quirks::URG);
    } else {
        tcp_sig.set_quirk(Quirks::NZ_URG, tcp_header.urg_ptr != 0);
    }

    tcp_sig.set_quirk(Quirks::PUSH, tcp_header.psh() != 0);
    tcp_sig.win = tcp_header.window;

    // let's do tcp options
    let mut tcp_option_pos = match unsafe { ctx.ptr_after(tcp_header as *const tcphdr) } {
        Ok(pos) => pos as *const u8 as usize,
        Err(_) => return false,
    };

    let tcp_option_end = tcp_header as *const tcphdr as usize + (tcp_header.doff() * 4) as usize;
    if tcp_option_end > ctx.data_end() {
        return false;
    }

    tcp_sig.pay_class = (ctx.data_end() != tcp_option_end) as i8;

    // unsafe {
    //     log_events.insert(&ctx, &MapData::new(tcp_option_pos as usize));
    // }

    for _ in 0..p0f::MAX_TCP_OPT - 6 {
        if tcp_option_pos >= tcp_option_end {
            return true;
        }

        // return true means finished
        if parse_tcp_option(ctx, &mut tcp_option_pos, tcp_option_end, tcp_sig) {
            break;
        }
    }

    if tcp_option_pos != tcp_option_end {
        tcp_sig.set_quirk(Quirks::OPT_BAD, true);
    }

    true
}

// this function is tedious, especially the way handle tcp_option_pos, it would be nice to find
// a way to simplify it and pass the Linux BPF verifier
#[inline(never)]
// #[inline(always)]
fn parse_tcp_option(
    ctx: &XdpContext,
    tcp_option_pos: &mut usize,
    tcp_option_end: usize,
    tcp_sig: &mut TcpSignature,
) -> bool {
    let data_end = ctx.data_end();

    let tcp_opt = unsafe { *(*tcp_option_pos as *const u8) };
    tcp_sig.add_opt(tcp_opt);

    // skip the opt kind byte
    if *tcp_option_pos + 2 > data_end {
        return true;
    }
    *tcp_option_pos += 1;

    match tcp_opt {
        //  EOL is a single-byte option that aborts further option parsing.
        p0f::TCPOPT_EOL => unsafe {
            // EOL is a single-byte option that aborts further option parsing.
            // Take note of how many bytes of option data are left, and if any of them are non-zero
            if *tcp_option_pos < tcp_option_end {
                tcp_sig.opt_eol_pad = (tcp_option_end - *tcp_option_pos) as u8;

                // the padding is used to make sure tcp header is 32bit aligned, so it should be 4 bytes at most
                for _ in 0..4 {
                    if *(*tcp_option_pos as *const u8) != 0 as u8 {
                        tcp_sig.set_quirk_true(Quirks::OPT_EOL_NZ);
                        return true;
                    }

                    if *tcp_option_pos + 2 > data_end || *tcp_option_pos + 2 > tcp_option_end {
                        return true;
                    }
                    *tcp_option_pos += 1;
                }
            }
            return true;
        },

        // MSS is a four-byte option with specified size: type, len, mss (u16)
        p0f::TCPOPT_MSS => unsafe {
            if *tcp_option_pos + core::mem::size_of::<TcpOptionMss>() > data_end {
                return true;
            }
            let tcp_opt_mss: *const TcpOptionMss = *tcp_option_pos as *const TcpOptionMss;

            if (*tcp_opt_mss).len != 4 as u8 {
                tcp_sig.set_quirk_true(Quirks::OPT_BAD);
            }
            tcp_sig.mss = i16::from_be((*tcp_opt_mss).mss) as i32;

            if *tcp_option_pos + 4 > data_end {
                return true;
            }
            *tcp_option_pos += 3;
        },

        //  WS is a three-byte option with specified size: type, len, shift
        p0f::TCPOPT_WSCALE => unsafe {
            if *tcp_option_pos + core::mem::size_of::<TcpOptionWscale>() > data_end {
                return true;
            }
            let tcp_opt_wscale: *const TcpOptionWscale = *tcp_option_pos as *const TcpOptionWscale;

            if (*tcp_opt_wscale).len != 3 as u8 {
                tcp_sig.set_quirk_true(Quirks::OPT_BAD);
            }

            tcp_sig.wscale = (*tcp_opt_wscale).wscale as i16;
            if tcp_sig.wscale > 14 {
                tcp_sig.set_quirk_true(Quirks::OPT_EXWS);
            }

            if *tcp_option_pos + 3 > data_end {
                return true;
            }
            *tcp_option_pos += 2;
        },

        //  SACKOK is a two-byte option with specified size
        p0f::TCPOPT_SACKOK => unsafe {
            if *tcp_option_pos + core::mem::size_of::<TcpOptionSackok>() > data_end {
                return true;
            }
            let tcp_opt_sackok: *const TcpOptionSackok = *tcp_option_pos as *const TcpOptionSackok;

            if (*tcp_opt_sackok).len != 2 as u8 {
                tcp_sig.set_quirk_true(Quirks::OPT_BAD);
            }

            if *tcp_option_pos + 2 > data_end {
                return true;
            }
            *tcp_option_pos += 1;
        },

        // SACK is a variable-length option of 10 to 34 bytes
        p0f::TCPOPT_SACK => unsafe {
            if *tcp_option_pos + core::mem::size_of::<TcpOptionU32>() > data_end {
                return true;
            }
            let tcp_opt_sack: *const TcpOptionU32 = *tcp_option_pos as *const TcpOptionU32;

            let len = (*tcp_opt_sack).len;
            if len < 10 as u8 || len > 34 as u8 {
                tcp_sig.set_quirk_true(Quirks::OPT_BAD);
                return true;
            }

            if len == 10 {
                if *tcp_option_pos + 10 > data_end {
                    return true;
                }
                *tcp_option_pos += 9;
            } else if len == 18 {
                if *tcp_option_pos + 18 > data_end {
                    return true;
                }
                *tcp_option_pos += 17;
            } else if len == 26 {
                if *tcp_option_pos + 26 > data_end {
                    return true;
                }
                *tcp_option_pos += 25;
            } else if len == 34 {
                if *tcp_option_pos + 34 > data_end {
                    return true;
                }
                *tcp_option_pos += 33;
            } else {
                tcp_sig.set_quirk_true(Quirks::OPT_BAD);
                return true;
            };
        },

        // Timestamp is a ten-byte option with specified size
        p0f::TCPOPT_TSTAMP => unsafe {
            if *tcp_option_pos + core::mem::size_of::<TcpOptionU32>() > data_end {
                return true;
            }
            let tcp_opt_tstamp: *const TcpOptionU32 = *tcp_option_pos as *const TcpOptionU32;

            if (*tcp_opt_tstamp).len != 10 as u8 {
                tcp_sig.set_quirk_true(Quirks::OPT_BAD);
            }

            tcp_sig.ts1 = u32::from_be((*tcp_opt_tstamp).u32_1);
            tcp_sig.set_quirk(Quirks::OPT_ZERO_TS1, tcp_sig.ts1 == 0);
            tcp_sig.set_quirk(Quirks::OPT_NZ_TS2, (*tcp_opt_tstamp).u32_2 != 0);

            if *tcp_option_pos + 10 > data_end {
                return true;
            }
            *tcp_option_pos += 9;
        },

        // NOP is a single-byte option that does nothing
        // others just keep move forward
        _other => {}
    };

    false
}

// #[inline(always)]
#[inline(never)]
fn parse_ipv4_tcp_signatures(
    ctx: &XdpContext,
    ip_header: &iphdr,
    tcp_sig: &mut TcpSignature,
) -> bool {
    let header_len = ip_header.ihl() as usize * 4;
    if header_len < core::mem::size_of::<iphdr>() {
        return false;
    }

    let tcp_header: *const tcphdr = {
        let addr = ip_header as *const iphdr as usize + header_len;
        if ip_header.protocol as u32 != IPPROTO_TCP
            || addr + core::mem::size_of::<tcphdr>() > ctx.data_end()
        {
            return false;
        } else {
            addr as *const tcphdr
        }
    };

    let tcp_header = unsafe { tcp_header.as_ref() }.unwrap();
    let dest_port = u16::from_be(tcp_header.dest);
    if dest_port != p0f::HTTP_PORT && dest_port != p0f::HTTPS_PORT
        || tcp_header.syn() == 0
        || tcp_header.ack() != 0
    {
        return false;
    }

    // set IPv4 header signature
    tcp_sig.ip_ver = 0x04;
    tcp_sig.ttl = ip_header.ttl;
    tcp_sig.ip_opt_len = header_len.saturating_sub(20) as u8;
    tcp_sig.tot_hdr = header_len as u16;

    // ECN is the last two bits of ToS
    tcp_sig.set_quirk(Quirks::ECN, (ip_header.tos & (p0f::IP_TOS_ECN)) != 0);

    let ip_flags = u16::from_be(ip_header.frag_off);
    tcp_sig.set_quirk(Quirks::NZ_MBZ, (ip_flags & p0f::IP4_MBZ) != 0);
    if (ip_flags & p0f::IP4_DF) != 0 {
        tcp_sig.set_quirk_true(Quirks::DF);
        tcp_sig.set_quirk(Quirks::NZ_ID, ip_header.id != 0);
    } else {
        tcp_sig.set_quirk(Quirks::ZERO_ID, ip_header.id == 0);
    }

    parse_tcp_signature(ctx, &tcp_header, tcp_sig)
}

#[xdp("p0f_extractor")]
pub fn p0f_extractor(ctx: XdpContext) -> XdpResult {
    let mut tcp_sig = TcpSignature::default();
    let eth = ctx.eth()?;
    unsafe {
        if (*eth).h_proto == u16::from_be(ETH_P_IP as u16) {
            let ip_header: *const iphdr = ctx.ptr_after(eth)?;

            if parse_ipv4_tcp_signatures(&ctx, &*ip_header, &mut tcp_sig) {
                tcp_signatures.insert(&ctx, &MapData::new(tcp_sig));
            }
        } else {
            // might other process, e.g. IPv6
            return Ok(XdpAction::Pass);
        };
    }

    Ok(XdpAction::Pass)
}
