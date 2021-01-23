use super::super::utils;

/// IPV6 Header structure
///
/// The IPV6 Header structure define the field of an IPV6 message on network
/// it have a fixed length of 40 bytes.
/// * `version_traffic_class_flow_label` contains three field
///   - version, constant value of 6 encoded on 4 bits
///   - traffic_class, hold two values, 6 first bits for traffic classification called DS field and 2 bytes for explicit congestion notification use for network congestion
///   - flow label, 20bits to labelise a numbers of packets between a source and a destination. 
/// * `payload_length`, lenght of the remaining payload, 0 for 
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

#[repr(C, packed)]
pub struct IPV6Header {
	pub version_traffic_class_flow_label: u32,
	pub payload_length: u16,
	pub next_header: u8,
	pub hop_limit: u8,
	pub src: [u32;4],
	pub dst: [u32;4],
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
///match utils::cast::cast_slice_to_reference::<EthernetHeader>(data) {
///		Ok(header) => {
///     let t = header.ether_type.to_be();
///			let current_data = &data[std::mem::size_of::<EthernetHeader>()..];
///		     match t {
///		      ETHERNET_TYPE_IPV6 => ipv6::decode(current_data),
///		      _ => println!("Not ipv6: {:?}", t),
///		    }
///		},
///		Err(msg) => {
///			println!("Error::ethernet {:?}", msg);
///		}
///	}
///```

pub fn decode(data: &[u8]) {
	match utils::cast::cast_slice_to_reference::<IPV6Header>(data) {
		Ok(header) => {
			let version = (header.version_traffic_class_flow_label & 0xF0) >> 4;
			if version != 6 {
				println!("Invalid ipv6 version: {:?}", version);
			} else {
				println!("protocol: ipv6 decoded");
			}
		},
		Err(msg) => {
			println!("ipv6 decode error: {:?}", msg);
		}
	}
}
