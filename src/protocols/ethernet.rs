use super::super::utils;

#[repr(C, packed)]
pub struct EthernetHeader {
    pub dhost: [u8; 6],
    pub shost: [u8; 6],
    pub ether_type: u16,
}

pub fn decode(data: &[u8]) {
	match utils::cast::cast_slice_to_reference::<EthernetHeader>(data) {
		Ok(header) => {
			let t = header.ether_type.to_be();
		    match t {
		        0x0806 => println!("arp"),
		        _ => println!("unknow: {:?}", t),
		    }
		},
		Err(msg) => {
			println!("Error: {:?}", msg);
		}
	}
    
}
