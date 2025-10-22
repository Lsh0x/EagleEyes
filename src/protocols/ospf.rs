// OSPFv2 minimal decoder (RFC 2328)
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub version: u8,
    pub typ: u8,
    pub pkt_len: u16,
    pub router_id: u32,
    pub area_id: u32,
    pub checksum: u16,
    pub auth_type: u16,
    pub auth: [u8; 8],
}

impl Header {
    pub const SIZE: usize = 24;
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let h = unsafe { &*(data.as_ptr() as *const Header) };
    println!(
        "OSPFv{} type={} len={} rid={:#010x} area={:#010x}",
        h.version,
        h.typ,
        u16::from_be(h.pkt_len),
        u32::from_be(h.router_id),
        u32::from_be(h.area_id)
    );
}
