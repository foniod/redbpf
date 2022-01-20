use core::mem;
use redbpf_probes::{bindings::iphdr, bindings::tcphdr, xdp::prelude::*};

#[repr(C)]
#[derive(Debug)]
pub struct TcpSignature {
    pub quirks: u32,     /* Quirks                             */
    pub opt_eol_pad: u8, /* Amount of padding past EOL         */
    pub ip_opt_len: u8,  /* Length of IP options               */
    pub ip_ver: i8,      /* -1 = any, IP_VER4, IP_VER6         */
    pub ttl: u8,         /* Actual TTL                         */

    pub mss: i32, /* Maximum segment size (-1 = any)    */
    pub win: u16, /* Window size                        */

    pub win_type: u8,  /* WIN_TYPE_*                         */
    pub pay_class: i8, /* -1 = any, 0 = zero, 1 = non-zero   */

    pub wscale: i16,  /* Window scale (-1 = any)            */
    pub tot_hdr: u16, /* Total header length                */
    pub ts1: u32,     /* Own timestamp                      */

    pub opt_cnt: u8,
    pub options: [u8; MAX_TCP_OPT],
}

// names from p0f
#[allow(non_camel_case_types)]
pub enum Quirks {
    /* IP-level quirks: */
    ECN = 0x00000001,     /* ECN supported                      */
    DF = 0x00000002,      /* DF used (probably PMTUD)           */
    NZ_ID = 0x00000004,   /* Non-zero IDs when DF set           */
    ZERO_ID = 0x00000008, /* Zero IDs when DF not set           */
    NZ_MBZ = 0x00000010,  /* IP "must be zero" field isn't      */
    FLOW = 0x00000020,    /* IPv6 flows used                    */

    /* Core TCP quirks: */
    ZERO_SEQ = 0x00001000, /* SEQ is zero                        */
    NZ_ACK = 0x00002000,   /* ACK non-zero when ACK flag not set */
    ZERO_ACK = 0x00004000, /* ACK is zero when ACK flag set      */
    NZ_URG = 0x00008000,   /* URG non-zero when URG flag not set */
    URG = 0x00010000,      /* URG flag set                       */
    PUSH = 0x00020000,     /* PUSH flag on a control packet      */

    /* TCP option quirks: */
    OPT_ZERO_TS1 = 0x01000000, /* Own timestamp set to zero          */
    OPT_NZ_TS2 = 0x02000000,   /* Peer timestamp non-zero on SYN     */
    OPT_EOL_NZ = 0x04000000,   /* Non-zero padding past EOL          */
    OPT_EXWS = 0x08000000,     /* Excessive window scaling           */
    OPT_BAD = 0x10000000,      /* Problem parsing TCP options        */
}

// IP-level ECN, last two bits
pub const IP_TOS_ECN: u8 = 0x03;

/* IP flags: */
pub const IP4_MBZ: u16 = 0x8000; /* "Must be zero"                  */
pub const IP4_DF: u16 = 0x4000; /* Don't fragment (usually PMTUD)  */
pub const IP4_MF: u16 = 0x2000; /* More fragments coming           */

pub const MIN_TCP4: usize = mem::size_of::<iphdr>() + mem::size_of::<tcphdr>();
pub const MIN_TCP6: usize = mem::size_of::<ipv6hdr>() + mem::size_of::<tcphdr>();

pub const HTTP_PORT: u16 = 80;
pub const HTTPS_PORT: u16 = 443;

// tcp_sig_match uses 10, here use 11 to make TcpSignature 4 bytes aligned
pub const MAX_TCP_OPT: usize = 11;
pub const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();

/* Notable options, aligned with p0f */
pub const TCPOPT_EOL: u8 = 0; // End of options (1)
pub const TCPOPT_NOP: u8 = 1; // No-op (1)
pub const TCPOPT_MSS: u8 = 2; // Maximum segment size (4)
pub const TCPOPT_WSCALE: u8 = 3; // Window scaling (3)
pub const TCPOPT_SACKOK: u8 = 4; // Selective ACK permitted (2)
pub const TCPOPT_SACK: u8 = 5; // Actual selective ACK (10-34)
pub const TCPOPT_TSTAMP: u8 = 8; // Timestamp (10)

/* Methods for matching window size in tcp_sig: */
pub const WIN_TYPE_NORMAL: u8 = 0x00; /* Literal value                      */
pub const WIN_TYPE_ANY: u8 = 0x01; /* Wildcard (p0f.fp sigs only)        */
pub const WIN_TYPE_MOD: u8 = 0x02; /* Modulo check (p0f.fp sigs only)    */
pub const WIN_TYPE_MSS: u8 = 0x03; /* Window size MSS multiplier         */
pub const WIN_TYPE_MTU: u8 = 0x04; /* Window size MTU multiplier         */

impl TcpSignature {
    pub fn default() -> Self {
        TcpSignature {
            quirks: 0,
            opt_eol_pad: 0,
            ip_opt_len: 0,
            ip_ver: 0,
            ttl: 0,
            mss: 0,
            win: 0,
            win_type: WIN_TYPE_NORMAL,
            pay_class: -1,
            wscale: 0,
            tot_hdr: 0,
            ts1: 0,
            opt_cnt: 0,
            options: [0; MAX_TCP_OPT],
        }
    }

    #[inline]
    pub fn set_quirk(&mut self, quirk: Quirks, cond: bool) {
        // only set quirk when cond is true
        if cond {
            self.quirks |= quirk as u32;
        }
    }

    #[inline]
    pub fn set_quirk_true(&mut self, quirk: Quirks) {
        self.quirks |= quirk as u32;
    }

    #[inline]
    pub fn add_opt(&mut self, opt: u8) {
        // it is always safe because the tcp option loop count <= MAX_TCP_OPT
        self.options[self.opt_cnt as usize] = opt;
        self.opt_cnt += 1;
    }
}

#[repr(C, packed)]
pub struct TcpOptionMss {
    pub len: u8,
    pub mss: i16,
}

#[repr(C, packed)]
pub struct TcpOptionWscale {
    pub len: u8,
    pub wscale: u8,
}

#[repr(C, packed)]
pub struct TcpOptionSackok {
    pub len: u8,
}

#[repr(C, packed)]
pub struct TcpOptionU32 {
    pub len: u8,
    pub u32_1: u32,
    pub u32_2: u32,
}
