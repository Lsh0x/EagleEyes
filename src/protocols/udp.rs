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

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let (hdr_bytes, payload) = data.split_at(Header::SIZE);
    match cow_struct::<Header>(hdr_bytes) {
        Some(h) => {
            let src = u16::from_be(h.src_port);
            let dst = u16::from_be(h.dest_port);
            // simple DNS detection
            if src == 53 || dst == 53 {
                dns::decode(payload);
            } else {
                println!(
                    "protocol::udp src={} dst={} len={}",
                    src,
                    dst,
                    u16::from_be(h.len)
                );
            }
        }
        None => println!("udp decode error: {:?}", "Truncated payload"),
    }
}
