use crate::utils::cow_struct;
use std::mem::size_of;

use super::ah;
use super::esp;
use super::ip;

/// IPV6 Header structure
///
/// The IPV6 Header structure define the field of an IPV6 message on network
/// it have a fixed length of 40 bytes.
/// * `version_traffic_class_flow_label` contains three field
///   - version, constant value of 6 encoded on 4 bits
///   - traffic_class, hold two values, 6 first bits for traffic classification called DS field and 2 bytes for explicit congestion notification use for network congestion
///   - flow label, 20bits to labelise a numbers of packets between a source and a destination.
/// * `payload_len`, lenght of the remaining payload, 0 for
/// * `next_header`, specify the type of the next header usually the transport layer protocol
/// * `hop_limit`, replace time to live field from ipv4, it's the limit of nnodes that the packet can be forwar.
/// * `src`, protocol address of the source
/// * `dst`, protocol address of the destination
///
/// Sources:
/// * https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
/// * https://en.wikipedia.org/wiki/Differentiated_services
/// * https://tools.ietf.org/html/rfc6437
/// * https://en.wikipedia.org/wiki/Explicit_Congestion_Notification

#[derive(Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    /// contains version traffic class and flow label
    pub version_traffic_class_flow_label: u32,
    /// length of the payload
    pub payload_len: u16,
    /// type of the next header
    pub next_header: u8,
    /// decremented at each node routing the packer
    pub hop_limit: u8,
    /// addresss of the source
    pub src: [u32; 4],
    /// address of the destination
    pub dst: [u32; 4],
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

/// Decode an ipv6 header packet for a given &[u8]
///
/// Will cast the given &[u8] into an ipv6 header struct allowing to interact with it.
/// It do not do any allocation for performance reason.
/// Usually called by the proto on top of it, like the ethernetHeader struct, that will
/// once the ethernet type have been detected to be arp, it can then decode the arp header using this.
///
/// # Examples:
///
///```
/// let (header_bytes, next_data) = data.split_at(EthernetHeader::SIZE);
/// match cow_struct::<EthernetHeader>(header_bytes) {
///     Some(header) => {
///         let t = header.ether_type.to_be();
///         match t {
///             PROTO::IPV6 => ipv6::decode(next_data),
///             _ => println!("ether type: {:?}", ether_type_as_str(t)),
///         }
///     None => println!("Error::ethernet {:?}", "Truncated payload"),
/// }
///```
pub fn decode(data: &[u8]) {
    if data.len() >= Header::SIZE {
        let (slice, next_data) = data.split_at(Header::SIZE);
        match cow_struct::<Header>(slice) {
            Some(header) => {
                let version = (header.version_traffic_class_flow_label & 0xF0) >> 4;
                if version != 6 {
                    println!("Invalid ipv6 version: {:?}", version);
                } else {
                    match header.next_header {
                        ip::PROTO::AH => ah::decode(next_data),
                        ip::PROTO::ESP => esp::decode(next_data),
                        _ => println!(
                            "protocol::ipv6 {:?}",
                            ip::protocol_as_str(header.next_header)
                        ),
                    }
                }
            }
            None => println!("ip decode error: {:?}", "Truncated payload"),
        }
    }
}
