use super::super::utils;

#[derive(Debug)]
pub struct ArpHeader {
  // hardware type
  pub h_type: u16,
  // protocol type
  pub p_type: u16,
  // hardware length (ex: 6 for mac addr)
  pub h_len: u8,
  // protocol length (ex: 4 for ipv4 addr)
  pub p_len: u8,
  // operation code
  pub op_code: u16,
}

pub fn decode(data: &[u8]) {
	match utils::cast::cast_slice_to_reference::<ArpHeader>(data) {
    Ok(header) => {
      let p_type = header.p_type.to_be();
      match p_type {
          0x800 => println!("Using ipv4"),
          0x86DD => println!("Using ipv6"),
          _ => println!("unknow: {:?}", p_type),
      }
    },
    Err(err) => println!("Error::arp {:?}", err),
  }
}
