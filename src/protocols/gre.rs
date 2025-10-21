use crate::utils::cow_struct;
use std::mem::size_of;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub flags_version: u16,
    pub protocol_type: u16,
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn display(h: &Header) -> String {
    format!(
        "GRE proto=0x{:04x} flags=0x{:04x}",
        h.protocol_type.to_be(),
        h.flags_version.to_be()
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
