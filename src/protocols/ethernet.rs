use super::super::utils;

use super::arp;
use super::ipv4;

#[repr(C, packed)]
pub struct EthernetHeader {
    pub dhost: [u8; 6],
    pub shost: [u8; 6],
    pub ether_type: u16,
}

const ETHERNET_TYPE_PUP: u16 = 0x0200;
const ETHERNET_TYPE_SPRITE: u16 = 0x0500;
const ETHERNET_TYPE_IP: u16 = 0x0800;
const ETHERNET_TYPE_ARP: u16 = 0x0806;
const ETHERNET_TYPE_REVARP: u16 = 0x8035;
const ETHERNET_TYPE_AT: u16 = 0x809B;
const ETHERNET_TYPE_AARP: u16 = 0x80F3;
const ETHERNET_TYPE_VLAN: u16 = 0x8100;
const ETHERNET_TYPE_IPX: u16 = 0x8137;
const ETHERNET_TYPE_IPV6: u16 = 0x86dd;
const ETHERNET_TYPE_LOOPBACK: u16 = 0x9000;

pub fn decode(data: &[u8]) {
	match utils::cast::cast_slice_to_reference::<EthernetHeader>(data) {
		Ok(header) => {
        	let t = header.ether_type.to_be();
			let current_data = &data[std::mem::size_of::<EthernetHeader>()..];
		    match t {
		    	ETHERNET_TYPE_PUP => println!("PUP"),
		    	ETHERNET_TYPE_SPRITE => println!("SPRITE"),
		    	ETHERNET_TYPE_IP => ipv4::decode(current_data),
		      ETHERNET_TYPE_ARP => arp::decode(current_data),
		      ETHERNET_TYPE_REVARP => println!("REVARP"),
		      ETHERNET_TYPE_AT => println!("AT"),
		      ETHERNET_TYPE_AARP => println!("AARP"),
		      ETHERNET_TYPE_VLAN => println!("VLAN"),
		      ETHERNET_TYPE_IPX => println!("IPX"),
		      ETHERNET_TYPE_IPV6 => println!("IPV6"),
		      ETHERNET_TYPE_LOOPBACK => println!("LOOPBACK"),
		      _ => println!("unknow: {:?}", t),
		    }
		},
		Err(msg) => {
			println!("Error::ethernet {:?}", msg);
		}
	}
}
