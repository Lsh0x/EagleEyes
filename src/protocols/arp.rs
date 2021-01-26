use super::super::utils;

#[non_exhaustive]
pub struct OP;

impl OP {
  pub const	REQUEST: u16 =	0x1;		/* ARP request.  */
  pub const REPLY: u16 =	0x2;		  /* ARP reply.  */
  pub const RREQUEST: u16 = 0x3;    /* RARP request.  */
  pub const RREPLY: u16 =	0x4;      /* RARP reply.  */
  pub const INREQUEST: u16 = 0x8;   /* InARP request.  */
  pub const INREPLY: u16 = 0x9;		  /* InARP reply.  */
  pub const NAK: u16 = 0xa;		      /* (ATM)ARP NAK.  */
}

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

impl std::fmt::Debug for ArpHeader {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, "h_type {:#x} ", self.h_type.to_be());
        write!(fmt, "p_type {:#x} ", self.p_type.to_be());
        write!(fmt, "h_len {:?} ", self.h_len.to_be());
        write!(fmt, "p_len {:?} ", self.p_len.to_be());
        write!(fmt, "op_code {:?} ", op_as_str(self.op_code.to_be()));
        return Ok(());
    }
}

pub fn decode(data: &[u8]) {
	match utils::cast::cast_slice_to_reference::<ArpHeader>(data) {
    Ok(header) => {
      println!("{:?}", header);
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
