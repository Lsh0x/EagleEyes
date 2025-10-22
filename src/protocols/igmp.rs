// IGMPv2 minimal decoder
use crate::utils::cow_struct;

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub typ: u8,
    pub max_resp_time: u8,
    pub checksum: u16,
    pub group_addr: u32,
}

impl Header {
    pub const SIZE: usize = 8;
}

pub fn display(h: &Header) -> String {
    let g = h.group_addr.to_be_bytes();
    format!(
        "IGMP type=0x{:02x} mrt={}cs checksum=0x{:04x} group={}.{}.{}.{}",
        h.typ,
        h.max_resp_time,
        u16::from_be(h.checksum),
        g[0],
        g[1],
        g[2],
        g[3]
    )
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let (hdr, _) = data.split_at(Header::SIZE);
    if let Some(h) = cow_struct::<Header>(hdr) {
        println!("{}", display(&h));
    }
}
