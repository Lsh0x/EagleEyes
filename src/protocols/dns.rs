use crate::utils::cow_struct;
use std::mem::size_of;

/// Minimal DNS header (RFC 1035)
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        println!("dns: truncated");
        return;
    }
    let (hdr_bytes, _rest) = data.split_at(Header::SIZE);
    match cow_struct::<Header>(hdr_bytes) {
        Some(h) => {
            println!(
                "protocol::dns id={} qd={} an={} ns={} ar={}",
                u16::from_be(h.id),
                u16::from_be(h.qdcount),
                u16::from_be(h.ancount),
                u16::from_be(h.nscount),
                u16::from_be(h.arcount)
            );
        }
        None => println!("dns decode error: {:?}", "Truncated payload"),
    }
}
