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
/// The ArpHeader define all the field of an arp request header
/// * `h_type` for the harware type, like ethernet for example
/// * `p_type` for the protocol type, like ip for example
/// * `h_len` for the hardware address length, corresponding of the number of bytes for the hardware address, example 6 for mac addresses
/// * `p_len` for the protocol address length, corresponding of the number of bytes for the protocol address, example 4 for ipv4 addresses
/// * `op_code` for the operation code, defined by the OP struct
#[derive(Default, Clone, Copy)]
#[repr(C, packed)]
pub struct ArpHeader {
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

impl ArpHeader {
    pub const SIZE: usize = size_of::<Self>();
}

impl fmt::Debug for ArpHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("ArpHeader")
            .field("h_type", &self.h_type.to_be())
            .field("p_type", &self.p_type.to_be())
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
///match utils::cast::cast_slice_to_reference::<EthernetHeader>(data) {
///   Ok(header) => {
///      let t = header.ether_type.to_be();
///     let current_data = &data[std::mem::size_of::<EthernetHeader>()..];
///       match t {
///         ETHERNET_TYPE_ARP => arp::decode(current_data),
///         _ => println!("Not ARP: {:?}", t),
///       }
///   },
///   Err(msg) => {
///     println!("Error::ethernet {:?}", msg);
///   }
/// }
///```
pub fn decode(data: &[u8]) {
    if data.len() >= ArpHeader::SIZE {
        let (slice, _data) = data.split_at(ArpHeader::SIZE);
        match cow_struct::<ArpHeader>(slice) {
            Some(header) => {
                println!("{:#?}", header);
                let p_type = header.p_type.to_be();
                match p_type {
                    0x800 => println!("Using ipv4"),
                    0x86DD => println!("Using ipv6"),
                    _ => println!("unknow: {:?}", p_type),
                }
            }
            None => println!("Error::arp {:?}", "Truncated payload"),
        }
    }
}
