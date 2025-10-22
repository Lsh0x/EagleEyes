// DHCPv6 minimal decoder (RFC 8415)
use crate::utils::cow_struct;

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub msg_type: u8,
    pub xid: [u8; 3],
}

impl Header {
    pub const SIZE: usize = 4;
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let (hdr, _) = data.split_at(Header::SIZE);
    if let Some(h) = cow_struct::<Header>(hdr) {
        let xid = u32::from_be_bytes([0, h.xid[0], h.xid[1], h.xid[2]]);
        println!("DHCPv6 type={} xid=0x{:06x}", h.msg_type, xid);
    }
}
