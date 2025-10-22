// DCCP minimal decoder (RFC 4340)
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Header8 {
    pub src_port: u16,
    pub dst_port: u16,
    pub data_offset_ccval_cscov: u8,
    pub checksum: u16,
    pub res_type_x: u8,
    pub seq_hi: u16,
    pub seq_lo: u16,
}

pub fn decode(data: &[u8]) {
    if data.len() < 12 {
        println!("DCCP (truncated) {}B", data.len());
        return;
    }
    let h = unsafe { &*(data.as_ptr() as *const Header8) };
    let src = u16::from_be(h.src_port);
    let dst = u16::from_be(h.dst_port);
    let doff = (h.data_offset_ccval_cscov & 0xF0) >> 4;
    let typ = h.res_type_x & 0x0F;
    println!("DCCP {} -> {} type={} doff={}", src, dst, typ, doff);
}
