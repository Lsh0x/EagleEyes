use crate::utils::cow_struct;
use std::mem::size_of;

// Minimal BOOTP/DHCP header (no options parsed here)
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: u32,
    pub yiaddr: u32,
    pub siaddr: u32,
    pub giaddr: u32,
    pub chaddr: [u8; 16],
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn display(h: &Header) -> String {
    let yi = h.yiaddr.to_be_bytes();
    let ci = h.ciaddr.to_be_bytes();
    format!(
        "DHCP op={} xid=0x{:08x} ciaddr={}.{}.{}.{} yiaddr={}.{}.{}.{}",
        h.op,
        h.xid.to_be(),
        ci[0],
        ci[1],
        ci[2],
        ci[3],
        yi[0],
        yi[1],
        yi[2],
        yi[3]
    )
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let (hdr, _rest) = data.split_at(Header::SIZE);
    if let Some(h) = cow_struct::<Header>(hdr) {
        println!("{}", display(&h));
    }
}
