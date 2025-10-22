// RTCP minimal decoder (RFC 3550)
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Header {
    pub v_p_count: u8,
    pub pt: u8,
    pub length: u16,
}

impl Header {
    pub const SIZE: usize = 4;
}

pub fn looks_like(data: &[u8]) -> bool {
    if data.len() < Header::SIZE {
        return false;
    }
    let v = data[0] & 0xC0;
    let pt = data[1];
    v == 0x80 && (200..=204).contains(&pt)
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        println!("RTCP (truncated) {}B", data.len());
        return;
    }
    let h = unsafe { &*(data.as_ptr() as *const Header) };
    println!("RTCP pt={} len={}", h.pt, u16::from_be(h.length));
}
