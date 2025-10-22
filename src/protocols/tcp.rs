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

pub fn display(h: &Header) -> String {
    format!(
        "TCP {} -> {} win={}",
        h.src_port.to_be(),
        h.dest_port.to_be(),
        h.win_size.to_be()
    )
}

pub fn decode(data: &[u8]) {
    if data.len() >= Header::SIZE {
        let (slice, _data) = data.split_at(Header::SIZE);
        match cow_struct::<Header>(slice) {
            Some(header) => {
                println!("{}", display(&header));
                let src = header.src_port.to_be();
                let dst = header.dest_port.to_be();
                let payload = if data.len() > Header::SIZE {
                    &data[Header::SIZE..]
                } else {
                    &data[0..0]
                };
                if src == 179 || dst == 179 {
                    super::bgp::decode(payload);
                } else if src == 22 || dst == 22 {
                    super::ssh::decode(payload);
                } else if src == 23 || dst == 23 {
                    super::telnet::decode(payload);
                } else if src == 21 || dst == 21 {
                    super::ftp::decode(payload);
                } else if src == 990 || dst == 990 {
                    // Implicit FTPS
                    if !super::tls::decode(payload) {
                        super::ftp::decode(payload);
                    }
                } else if src == 25 || dst == 25 || src == 587 || dst == 587 {
                    super::smtp::decode(payload);
                } else if src == 465 || dst == 465 {
                    super::smtps::decode(payload);
                } else if src == 110 || dst == 110 {
                    super::pop3::decode(payload);
                } else if src == 143 || dst == 143 {
                    super::imap::decode(payload);
                } else if src == 993 || dst == 993 {
                    if !super::tls::decode(payload) {
                        super::imap::decode(payload);
                    }
                } else if src == 389 || dst == 389 {
                    super::ldap::decode(payload);
                } else if src == 636 || dst == 636 {
                    super::ldaps::decode(payload);
                } else if src == 3389 || dst == 3389 {
                    super::rdp::decode(payload);
                } else if src == 139 || dst == 139 || src == 445 || dst == 445 {
                    super::smb::decode(payload);
                } else if src == 554 || dst == 554 {
                    super::rtsp::decode(payload);
                } else if src == 80
                    || dst == 80
                    || src == 8080
                    || dst == 8080
                    || src == 8000
                    || dst == 8000
                {
                    super::http::decode(payload);
                } else if src == 443 || dst == 443 {
                    // try TLS first
                    if !super::tls::decode(payload) {
                        // not TLS, maybe HTTP/1.1 in clear on 443 (rare)
                        super::http::decode(payload);
                    }
                }
            }
            None => println!("ip decode error: {:?}", "Truncated payload"),
        }
    }
}
