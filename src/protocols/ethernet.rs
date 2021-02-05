use crate::utils::cow_struct;
use std::mem::size_of;

use super::arp;
use super::ipv4;
use super::ipv6;

#[derive(Debug, Default, Clone, Copy)]
#[repr(C, packed)]
pub struct EthernetHeader {
    pub dhost: [u8; 6],
    pub shost: [u8; 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    pub const SIZE: usize = size_of::<Self>();
}

/// Ether type value for protocol encapsulation
///
/// This define values use to determine the protocol encapsulated in the ethernet frame
/// Value are defined by Internet Assigned Numbers Authority (IANA)
///
/// Source:
/// * https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
#[non_exhaustive]
pub struct PROTO;

impl PROTO {
    pub const PUP: u16 = 0x0200;
    pub const SPRITE: u16 = 0x0500;
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const REVARP: u16 = 0x8035;
    pub const AT: u16 = 0x809B;
    pub const AARP: u16 = 0x80F3;
    pub const VLAN: u16 = 0x8100;
    pub const IPX: u16 = 0x8137;
    pub const IPV6: u16 = 0x86dd;
    pub const LOOPBACK: u16 = 0x9000;
}

/// ether type protocol to str
///
/// Transform an u16 to a humain readable str
/// if the value of the given u16 match one of the value in ethernet::PROTO
/// then a str corresponding to the op code is returned
/// # Examples
/// ```
/// println!(op_as_str(0x1));   // will print REQUEST
/// println!(op_as_str(0x2a));  // will print UNKNOW
/// ```
pub fn ether_type_as_str(ether_type: u16) -> &'static str {
    match ether_type {
        PROTO::PUP => "PUP",
        PROTO::SPRITE => "SPRITE",
        PROTO::IPV4 => "IPV4",
        PROTO::ARP => "ARP",
        PROTO::REVARP => "REVARP",
        PROTO::AT => "AT",
        PROTO::AARP => "AARP",
        PROTO::VLAN => "VLAN",
        PROTO::IPX => "IPX",
        PROTO::IPV6 => "IPV6",
        PROTO::LOOPBACK => "LOOPBACK",
        _ => "UNKNOW",
    }
}

pub fn decode(data: &[u8]) {
    if data.len() >= EthernetHeader::SIZE {
        let (header_bytes, next_data) = data.split_at(EthernetHeader::SIZE);
        match cow_struct::<EthernetHeader>(header_bytes) {
            Some(header) => {
                let t = header.ether_type.to_be();
                match t {
                    PROTO::ARP => arp::decode(next_data),
                    PROTO::IPV4 => ipv4::decode(next_data),
                    PROTO::IPV6 => ipv6::decode(next_data),
                    _ => println!("ether type: {:?}", ether_type_as_str(t)),
                }
            }
            None => println!("Error::ethernet {:?}", "Truncated payload"),
        }
    }
}
