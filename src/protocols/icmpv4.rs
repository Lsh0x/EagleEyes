use crate::utils::cow_struct;
use std::mem::size_of;

/// Internet Controle Message Protocol
///
/// The ICMPHeader is used in the internet protocol to send error messages and operational information indicating success or failure    
/// It is compose of 4 bytes that don't change, type, code, checksum and then 4 bytes depending on
/// the type and code provided
/// The strucute is the same for ipv4 and ipv6 but type and code differ
/// * `type` type code of the control message
/// * `code` code for the type  
/// * `checksum` internet checksum for error handling
/// Sources:
/// * https://tools.ietf.org/html/rfc777
#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    /// type of the control message
    pub t: u8,
    /// code of the controle message
    pub code: u8,
    /// internet checksum
    pub checksum: u16,
    /// rest of the header depending on type and code
    pub rest: u32,
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

/// Type of ICMP v4
///
/// This define value use for type of control message
#[non_exhaustive]
pub struct TYPE;

impl TYPE {
    /// echo reply
    pub const REPLY: u8 = 0x0;
    /// destination is not reachable
    pub const UNREACHABLE: u8 = 0x3;
    /// use to make sender decrease the rate of messages sent to a router or host
    pub const QUENCH: u8 = 0x4;
    /// use to redirect message
    pub const REDIRECT: u8 = 0x5;
    /// echo request
    pub const REQUEST: u8 = 0x8;
    /// timeout exeeded
    pub const EXEEDED: u8 = 0xb;
    /// paramters problem
    pub const PARAMSPROB: u8 = 0xc;
    /// synchronisattion of timestamp request
    pub const TIMESTAMP: u8 = 0xd;
    /// synchronisation of timestamp reply
    pub const TIMEREPLY: u8 = 0xe;
}

/// message code for ipv4 to str
///
/// Transform an u8 to a humain readable str
/// if the value of the given u8 match one of the value in ICMPV4::TYPE
/// then a str corresponding to the op code is returned
/// # Examples
/// ```
/// println!(icmp_v4_code_to_str(0x0));   // will print REPLY
/// println!(icmp_v4_code_to_str(0x43));  // will print UNKNOW
/// ```
fn icmp_v4_code_to_str(code: u8) -> &'static str {
    match code {
        TYPE::REPLY => "ECHO REPLY",
        TYPE::UNREACHABLE => "UNREACHABLE",
        TYPE::QUENCH => "QUENCH",
        TYPE::REDIRECT => "REDIRECT",
        TYPE::REQUEST => "ECHO REQUEST",
        TYPE::EXEEDED => "EXEEDED",
        TYPE::PARAMSPROB => "PARAMSPROB",
        TYPE::TIMESTAMP => "TIMESTAMP",
        TYPE::TIMEREPLY => "TIMEREPLY",
        _ => "UNKNOW",
    }
}

/// Decode an icmp v4 header packet for a given &[8]
///
/// Will cast the given &[8] into an icmpv4 header struct allowing to interact with it.
/// It do not do any allocation for performance reason.
/// Usually called by the proto on top of it, like the ethernetHeader struct, that will
/// once the ethernet type have been detected to be arp, it can then decode the arp header using this.
pub fn display(h: &Header) -> String {
    format!("ICMPv4 {}", icmp_v4_code_to_str(h.t.to_be()))
}

pub fn decode(data: &[u8]) {
    if data.len() >= Header::SIZE {
        let (header_bytes, _data) = data.split_at(Header::SIZE);
        match cow_struct::<Header>(header_bytes) {
            Some(header) => println!("{}", display(&header)),
            None => println!("Error::icmpv4 {:?}", "Truncated payload"),
        }
    }
}
