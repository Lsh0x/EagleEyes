use crate::utils::cow_struct;
use std::mem::size_of;

use super::ethernet;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub tci: u16,        // PCP(3) | DEI(1) | VID(12)
    pub ether_type: u16, // inner ether type
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn display(h: &Header) -> String {
    let vid = h.tci.to_be() & 0x0FFF;
    let pcp = (h.tci.to_be() & 0xE000) >> 13;
    format!(
        "802.1Q VLAN vid={} pcp={} inner={}",
        vid,
        pcp,
        ethernet::ether_type_as_str(h.ether_type.to_be())
    )
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let (hdr, payload) = data.split_at(Header::SIZE);
    if let Some(h) = cow_struct::<Header>(hdr) {
        println!("{}", display(&h));
        match h.ether_type.to_be() {
            ethernet::PROTO::IPV4 => super::ipv4::decode(payload),
            ethernet::PROTO::IPV6 => super::ipv6::decode(payload),
            ethernet::PROTO::ARP => super::arp::decode(payload),
            _ => println!(
                "vlan inner eth_type={}",
                ethernet::ether_type_as_str(h.ether_type.to_be())
            ),
        }
    }
}
