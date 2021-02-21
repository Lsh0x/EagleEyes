use crate::utils::cow_struct;
use std::mem::size_of;

/// TCP header
///
/// The Transmission Control Protocol provide an established and maintained connexion, and exange data stream between machine
/// and use check to ensure the delivery of packets.
/// Its the most wild use protocol nowdays
///
/// Sources
/// https://www.lifewire.com/tcp-headers-and-udp-headers-explained-817970
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    /// Port of the source
    pub src_port: u16,
    /// Port of the destination
    pub dest_port: u16,
    /// Message senders use sequence numbers to mark the ordering of a group of messages.
    pub seq_number: u32,
    /// Both senders and receivers use the acknowledgment numbers field to communicate the sequence numbers of messages that are either recently received or expected to be sent.
    pub seq_ack: u32,
    /// Size of the header in 4 bytes (header size 20bytes. data_offset egal to 5)
    pub data_offset: [u8; 4],
    /// Use for padding and allign memory
    pub reserved: [u8; 3],
    /// use to manage data flow
    pub control_flag: [u8; 9],
    /// Regulate how much data they send to a receiver before requiring an acknowledgment in return.
    pub win_size: u16,
    /// The checksum value is use to help the receiver detect messages that are corrupted or tampered with.
    pub checksum: u16,
    /// Can be used as a data offset to mark a subset of a message as requiring priority processing.
    pub urgent_ptr: u16,
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

pub fn decode(data: &[u8]) {
    if data.len() >= Header::SIZE {
        let (slice, _data) = data.split_at(Header::SIZE);
        match cow_struct::<Header>(slice) {
            Some(header) => {
                println!("protocol::tcp data {:#02x?}", header.data_offset);
            }
            None => println!("ip decode error: {:?}", "Truncated payload"),
        }
    }
}
