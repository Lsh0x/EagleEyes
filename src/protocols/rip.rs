// RIP v2 minimal decoder (UDP/520)
use crate::utils::cow_struct;

#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub cmd: u8,
    pub ver: u8,
    pub zero: u16,
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
        println!("RIP cmd={} ver={}", h.cmd, h.ver);
    }
}
