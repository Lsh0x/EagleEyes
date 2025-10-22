// RTP minimal decoder (RFC 3550)
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub v_p_x_cc: u8,
    pub m_pt: u8,
    pub seq: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

impl Header {
    pub const SIZE: usize = 12;
}

pub fn looks_like(data: &[u8]) -> bool {
    if data.len() < Header::SIZE {
        return false;
    }
    let v = data[0] & 0xC0; // version bits
    v == 0x80
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        println!("RTP (truncated) {}B", data.len());
        return;
    }
    let h = unsafe { &*(data.as_ptr() as *const Header) };
    let pt = h.m_pt & 0x7F;
    println!(
        "RTP v={} pt={} seq={} ts={} ssrc=0x{:08x}",
        (h.v_p_x_cc >> 6) & 3,
        pt,
        u16::from_be(h.seq),
        u32::from_be(h.timestamp),
        u32::from_be(h.ssrc)
    );
}
