use super::super::utils;

pub const	OP_REQUEST: u16 =	0x1;		/* ARP request.  */
pub const OP_REPLY: u16 =	0x2;		  /* ARP reply.  */
pub const OP_RREQUEST: u16 = 0x3;   /* RARP request.  */
pub const OP_RREPLY: u16 =	0x4;    /* RARP reply.  */
pub const OP_InREQUEST: u16 = 0x8;  /* InARP request.  */
pub const OP_InREPLY: u16 = 0x9;		/* InARP reply.  */
pub const OP_NAK: u16 = 0xa;		    /* (ATM)ARP NAK.  */

#[repr(C, packed)]
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
