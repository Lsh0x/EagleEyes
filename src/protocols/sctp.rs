// SCTP minimal common header (RFC 4960)
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub src_port: u16,
    pub dst_port: u16,
    pub vtag: u32,
    pub checksum: u32,
}

pub fn decode(data: &[u8]) {
    if data.len() < 12 {
        println!("SCTP (truncated) {}B", data.len());
        return;
    }
    let h = unsafe { &*(data.as_ptr() as *const Header) };
    println!(
        "SCTP {} -> {} vtag=0x{:08x}",
        u16::from_be(h.src_port),
        u16::from_be(h.dst_port),
        u32::from_be(h.vtag)
    );
}
