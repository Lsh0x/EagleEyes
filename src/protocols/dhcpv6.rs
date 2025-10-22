// DHCPv6 minimal decoder (RFC 8415)
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub msg_type: u8,
    pub xid: [u8; 3],
}

impl Header {
    pub const SIZE: usize = 4;
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let h = unsafe { &*(data.as_ptr() as *const Header) };
    let xid = ((h.xid[0] as u32) << 16) | ((h.xid[1] as u32) << 8) | (h.xid[2] as u32);
    println!("DHCPv6 type={} xid=0x{:06x}", h.msg_type, xid);
}
