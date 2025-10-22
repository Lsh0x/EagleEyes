use crate::utils::cow_struct;
use std::mem::size_of;

use super::dns;

/// UDP header
///
/// User Datagram Protocol is a connection-less transport protocol.
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub src_port: u16,
    pub dest_port: u16,
    pub len: u16,
    pub checksum: u16,
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn display(h: &Header) -> String {
    let src = u16::from_be(h.src_port);
    let dst = u16::from_be(h.dest_port);
    let len = u16::from_be(h.len);
    format!(
        "[UDP] src={} dst={} len={} checksum=0x{:04x}",
        src,
        dst,
        len,
        u16::from_be(h.checksum)
    )
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let (hdr_bytes, payload) = data.split_at(Header::SIZE);
    match cow_struct::<Header>(hdr_bytes) {
        Some(h) => {
            let src = u16::from_be(h.src_port);
            let dst = u16::from_be(h.dest_port);
            // protocol detection by port
            if src == 53 || dst == 53 {
                dns::decode(payload);
            } else if src == 5353 || dst == 5353 {
                super::mdns::decode(payload);
            } else if src == 67 || dst == 67 || src == 68 || dst == 68 {
                super::dhcp::decode(payload);
            } else if src == 123 || dst == 123 {
                super::ntp::decode(payload);
            } else if src == 546 || dst == 546 || src == 547 || dst == 547 {
                super::dhcpv6::decode(payload);
            } else if src == 520 || dst == 520 {
                super::rip::decode(payload);
            } else if src == 443 || dst == 443 {
                super::quic::decode(payload);
            } else {
                println!("{}", display(&h));
            }
        }
        None => println!("udp decode error: {:?}", "Truncated payload"),
    }
}
