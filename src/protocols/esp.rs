use crate::utils::cow_struct;
use std::mem::size_of;

/// Encapsulation Security payload
///
/// Design to provide security services, confidentiality, data origin authentification,
/// connectionless integrity, anti replay and limited traffic flow confidentiality
/// TODO: see how to get the size variable data and payload length to get next_data header
///
/// Sources:
/// * https://tools.ietf.org/html/rfc4303
/// * https://tools.ietf.org/html/rfc8221
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    /// security parameters index, random value to combine with the destination ip address and
    /// security protocol
    pub spi: u32,
    /// sequence number field, counter value increase at each node, proccess of this field is at
    /// the discretion of the receiver.
    pub seq_number: u32,
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn decode(data: &[u8]) {
    if data.len() >= Header::SIZE {
        let (header_bytes, _next_data) = data.split_at(Header::SIZE);
        match cow_struct::<Header>(header_bytes) {
            Some(_) => {
                println!("protocol::esp decoded");
            }
            None => println!("ip::esp decode error: {:?}", "Truncated payload"),
        }
    }
}
