use crate::utils::cow_struct;
use std::mem::size_of;

/// Internet Controle Message Protocol
///
/// The ICMPHeader is used in the internet protocol to send error messages and operational information indicating success or failure    
/// It is compose of 4 bytes that don't change, type, code, checksum and then 4 bytes depending on
/// the type and code provided
/// The strucute is the same for ipv6 and ipv6 but type and code differ
/// * `type` type code of the control message
/// * `code` code for the type  
/// * `checksum` internet checksum for error handling
/// Sources:
/// * https://tools.ietf.org/html/rfc777
#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct ICMPV6Header {
    /// type of the control message
    pub t: u8,
    /// code of the controle message
    pub code: u8,
    /// internet checksum
    pub checksum: u16,
    /// rest of the header depending on type and code
    pub rest: u32,
}

impl ICMPV6Header {
    pub const SIZE: usize = size_of::<Self>();
}

/// Type of ICMP v6
///
/// This define value use for type of control message
#[non_exhaustive]
pub struct TYPE;

impl TYPE {
    /// destination is not reachable
    pub const UNREACHABLE: u8 = 0x1;
    /// packet is too big
    pub const TOOBIG: u8 = 0x2;
    /// timeout exeeded
    pub const EXEEDED: u8 = 0x3;
    /// paramters problem
    pub const PARAMSPROB: u8 = 0x4;
    /// echo request
    pub const REQUEST: u8 = 0x80;
    /// echo reply
    pub const REPLY: u8 = 0x81;
}

/// message code for ipv6 to str
///
/// Transform an u8 to a humain readable str
/// if the value of the given u8 match one of the value in ICMPV6::TYPE
/// then a str corresponding to the op code is returned
/// # Examples
/// ```
/// println!(icmp_v6_code_to_str(0x0));   // will print REPLY
/// println!(icmp_v6_code_to_str(0x43));  // will print UNKNOW
/// ```
fn icmp_v6_code_to_str(code: u8) -> &'static str {
    match code {
        TYPE::UNREACHABLE => "UNREACHABLE",
        TYPE::TOOBIG => "TOOBIG",
        TYPE::EXEEDED => "EXEEDED",
        TYPE::PARAMSPROB => "PARAMSPROB",
        TYPE::REQUEST => "ECHO REQUEST",
        TYPE::REPLY => "ECHO REPLY",
        _ => "UNKNOW",
    }
}

/// Decode an icmp v6 header packet for a given &[8]
///
/// Will cast the given &[8] into an icmpv6 header struct allowing to interact with it.
/// It do not do any allocation for performance reason.
/// Usually called by the proto on top of it, like the ethernetHeader struct, that will
/// once the ethernet type have been detected to be arp, it can then decode the arp header using this.
pub fn decode(data: &[u8]) {
    if data.len() >= ICMPV6Header::SIZE {
        let (header_bytes, _data) = data.split_at(ICMPV6Header::SIZE);
        match cow_struct::<ICMPV6Header>(header_bytes) {
            Some(header) => println!(
                "protocol::icmpv6 type {:?}",
                icmp_v6_code_to_str(header.t.to_be())
            ),
            None => println!("Error::icmpv6 {:?}", "Truncated payload"),
        }
    }
}
