use crate::utils::cow_struct;
use std::mem::size_of;

use super::ip;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct IPV4Header {
    pub version_and_header_len: u8,
    pub type_of_service: u8,
    pub total_len: u16,
    pub identification: u16,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: u32,
    pub dst: u32,
}

impl IPV4Header {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn decode(data: &[u8]) {
    if data.len() >= IPV4Header::SIZE {
        let (slice, _data) = data.split_at(IPV4Header::SIZE);
        match cow_struct::<IPV4Header>(slice) {
            Some(header) => {
                let version = (header.version_and_header_len & 0xF0) >> 4;
                if version != 4 {
                    println!("Invalid ip version: {:?}", version);
                } else {
                    let len_bytes: usize = ((header.version_and_header_len & 0xF) * 32 / 8).into();
                    let _current_data = &data[len_bytes..];
                    println!("protocol {:?}", ip::protocol_as_str(header.protocol));
                }
            }
            None => println!("ip decode error: {:?}", "Truncated payload"),
        }
    }
}
