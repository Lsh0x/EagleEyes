use crate::utils::cow_struct;
use std::mem::size_of;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub flags: u8, // LI(2), VN(3), MODE(3)
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub ref_id: u32,
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn display(h: &Header) -> String {
    let li = (h.flags & 0b1100_0000) >> 6;
    let vn = (h.flags & 0b0011_1000) >> 3;
    let mode = h.flags & 0b0000_0111;
    let mode_name = match mode {
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        _ => "other",
    };
    format!(
        "[NTP] LI={} VN={} MODE={}({}) stratum={}",
        li, vn, mode, mode_name, h.stratum
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
