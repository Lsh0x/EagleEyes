use std::mem::size_of;
use crate::utils::cow_struct;

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

const IPPROTO_IP: u8 = 0;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_IGMP: u8 = 2;
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_EGP: u8 = 8;
const IPPROTO_PUP: u8 = 12;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_IDP: u8 = 22;
const IPPROTO_TP: u8 = 29;
const IPPROTO_DCCP: u8 = 33;
const IPPROTO_IPV6: u8 = 41;
const IPPROTO_RSVP: u8 = 46;
const IPPROTO_GRE: u8 = 47;
const IPPROTO_ESP: u8 = 50;
const IPPROTO_AH: u8 = 51;
const IPPROTO_MTP: u8 = 92;
const IPPROTO_BEETPH: u8 = 94;
const IPPROTO_ENCAP: u8 = 98;
const IPPROTO_PIM: u8 = 103;
const IPPROTO_COMP: u8 = 108;
const IPPROTO_SCTP: u8 = 132;
const IPPROTO_UDPLITE: u8 = 136;
const IPPROTO_MPLS: u8 = 137;
const IPPROTO_RAW: u8 = 255;

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
          match header.protocol {
            IPPROTO_IP => println!("IP"),
            IPPROTO_ICMP => println!("ICMP"),
            IPPROTO_IGMP => println!("IGMP"),
            IPPROTO_IPIP => println!("IPIP"),
            IPPROTO_TCP => println!("TCP"),
            IPPROTO_EGP => println!("EGP"),
            IPPROTO_PUP => println!("PUP"),
            IPPROTO_UDP => println!("UDP"),
            IPPROTO_IDP => println!("IDP"),
            IPPROTO_TP => println!("TP"),
            IPPROTO_DCCP => println!("DCCP"),
            IPPROTO_IPV6 => println!("IPV6"),
            IPPROTO_RSVP => println!("RSVP"),
            IPPROTO_GRE => println!("GRE"),
            IPPROTO_ESP => println!("ESP"),
            IPPROTO_AH => println!("AH"),
            IPPROTO_MTP => println!("MTP"),
            IPPROTO_BEETPH => println!("BEETPH"),
            IPPROTO_ENCAP => println!("ENCAP"),
            IPPROTO_PIM => println!("PIM"),
            IPPROTO_COMP => println!("COMP"),
            IPPROTO_SCTP => println!("SCTP"),
            IPPROTO_UDPLITE => println!("UDPLITE"),
            IPPROTO_MPLS => println!("MPLS"),
            IPPROTO_RAW => println!("RAW"),
            _ => println!("unknown protocol: {}", format!("{:#X}", header.protocol)),
          }
        }
      },
      None => println!("ip decode error: {:?}", "Truncated payload"),
    }
  }
}
