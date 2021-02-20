use super::ethernet;
use crate::utils::cow_struct;
use std::fmt;
use std::mem::size_of;

/// ARP op code
///
/// This define value use for operation code in arp message
/// Value are defined in the /usr/include/net/if_arp.h header
#[non_exhaustive]
pub struct OP;

impl OP {
    /// ARP request
    pub const REQUEST: u16 = 0x1;
    /// ARP reply
    pub const REPLY: u16 = 0x2;
    /// RARP request
    pub const RREQUEST: u16 = 0x3;
    /// RARP reply
    pub const RREPLY: u16 = 0x4;
    /// InARP request
    pub const INREQUEST: u16 = 0x8;
    /// InARP reply
    pub const INREPLY: u16 = 0x9;
    /// (ATM) ARP NAK
    pub const NAK: u16 = 0xa;
}

/// Arp op code to str
///
/// Transform an u16 to a humain readable str
/// if the value of the given u16 match one of the value in arp::OP
/// then a str corresponding to the op code is returned
/// # Examples
/// ```
/// println!(op_as_str(0x1));   // will print REQUEST
/// println!(op_as_str(0x2a));  // will print UNKNOW
/// ```
fn op_as_str(op: u16) -> &'static str {
    match op {
        OP::REQUEST => "REQUEST",
        OP::REPLY => "REPLY",
        OP::RREQUEST => "R_REQUEST",
        OP::RREPLY => "R_REPLY",
        OP::INREQUEST => "IN_REQUEST",
        OP::INREPLY => "IN_REPLY",
        OP::NAK => "NAK",
        _ => "UNKNOW",
    }
}

/// ARP Header structure
///
/// The Header define all the field of an arp request header
/// * `h_type` for the harware type, like ethernet for example
/// * `p_type` for the protocol type, like ip for example
/// * `h_len` for the hardware address length, corresponding of the number of bytes for the hardware address, example 6 for mac addresses
/// * `p_len` for the protocol address length, corresponding of the number of bytes for the protocol address, example 4 for ipv4 addresses
/// * `op_code` for the operation code, defined by the OP struct
#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    /// hardware type
    pub h_type: u16,
    /// protocol type
    pub p_type: u16,
    /// hardware length (ex: 6 for mac addr)
    pub h_len: u8,
    /// protocol length (ex: 4 for ipv4 addr)
    pub p_len: u8,
    /// operation code
    pub op_code: u16,
}

impl Header {
    pub const SIZE: usize = size_of::<Self>();
}

impl fmt::Debug for Header {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Header")
            .field("h_type", &self.h_type.to_be())
            .field("p_type", &ethernet::ether_type_as_str(self.p_type.to_be()))
            .field("h_len", &self.h_len.to_be())
            .field("p_len", &self.p_len.to_be())
            .field("op_code", &op_as_str(self.op_code.to_be()))
            .finish()
    }
}

/// Decode an arp header packet for a given &[8]
///
/// Will cast the given &[8] into an arp header struct allowing to interact with it.
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
///             PROTO::ARP => arp::decode(next_data),
///             _ => println!("ether type: {:?}", ether_type_as_str(t)),
///         }
///     None => println!("Error::ethernet {:?}", "Truncated payload"),
/// }
///```
pub fn decode(data: &[u8]) {
    if data.len() >= Header::SIZE {
        let (header_bytes, _data) = data.split_at(Header::SIZE);
        match cow_struct::<Header>(header_bytes) {
            Some(header) => println!("{:#?}", header),
            None => println!("Error::arp {:?}", "Truncated payload"),
        }
    }
}
