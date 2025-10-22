// EIGRP minimal header decoder
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub version: u8,
    pub opcode: u8,
    pub checksum: u16,
    pub flags: u32,
    pub seq: u32,
    pub ack: u32,
    pub asn: u32,
}

impl Header {
    pub const SIZE: usize = 20;
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        return;
    }
    let h = unsafe { &*(data.as_ptr() as *const Header) };
    println!(
        "EIGRP v{} op={} flags=0x{:08x} seq={} ack={} asn={}",
        h.version,
        h.opcode,
        u32::from_be(h.flags),
        u32::from_be(h.seq),
        u32::from_be(h.ack),
        u32::from_be(h.asn)
    );
}
