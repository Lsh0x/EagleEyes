use crate::utils::cow_struct;
use std::mem::size_of;

use super::ip;

/// Authentication header
///
/// The IP protocol allow to add extra header to the request
/// Its use to provide connectionless intergrity and data origin for IP datagram
/// and provide protection against replay
/// Its following by the authentication data, that we didn't represent in this structure
/// since its length is variable.
///
/// Sources
/// * https://tools.ietf.org/html/rfc4302
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AHHeader {
    /// type of the next header
    pub next_header: u8,
    /// length of the authentication data following the header
    pub payload_len: u16,
    /// reserved for future used
    pub reserved: u16,
    /// security parameters index, random value to combine with the destination ip address and
    /// security protocol
    pub spi: u32,
    /// sequence number field, counter value increase at each node, proccess of this field is at
    /// the discretion of the receiver.
    pub seq_number: u32,
}

impl AHHeader {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn decode(data: &[u8]) {
    if data.len() >= AHHeader::SIZE {
        let (slice, _data) = data.split_at(AHHeader::SIZE);
        match cow_struct::<AHHeader>(slice) {
            Some(header) => {
                println!(
                    "protocol {:?}",
                    ip::protocol_as_str(header.next_header.to_be())
                );
            }
            None => println!("ip decode error: {:?}", "Truncated payload"),
        }
    }
}
