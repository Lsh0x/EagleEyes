use super::super::utils;

#[repr(C, packed)]
pub struct EthernetHeader {
    pub dhost: [u8; 6],
    pub shost: [u8; 6],
    pub ether_type: u16,
}

pub fn decode(data: &[u8]) {
	let header = utils::cast::cast_slice_to_reference::<EthernetHeader>(data);
    let t = header.ether_type.to_be();
    match t {
        0x0806 => println!("arp"),
        _ => println!("unknow: {:?}", t),
    }
}
