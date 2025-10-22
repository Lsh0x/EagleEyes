// RTP minimal decoder (RFC 3550)
use crate::utils::cow_struct;

#[derive(Default, Clone, Copy)]
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
    if v != 0x80 {
        return false;
    }
    let pt = data[1] & 0x7F;
    // Exclude RTCP payload type range
    if (200..=204).contains(&pt) {
        return false;
    }
    true
}

pub fn decode(data: &[u8]) {
    if data.len() < Header::SIZE {
        println!("RTP (truncated) {}B", data.len());
        return;
    }
    let (hdr, _) = data.split_at(Header::SIZE);
    if let Some(h) = cow_struct::<Header>(hdr) {
        let m = (h.m_pt & 0x80) != 0;
        let pt = h.m_pt & 0x7F;
        let cc = h.v_p_x_cc & 0x0F;
        println!(
            "RTP v={} pt={} M={} CC={} seq={} ts={} ssrc=0x{:08x}",
            (h.v_p_x_cc >> 6) & 3,
            pt,
            m as u8,
            cc,
            u16::from_be(h.seq),
            u32::from_be(h.timestamp),
            u32::from_be(h.ssrc)
        );
    } else {
        println!("RTP (truncated) {}B", data.len());
    }
}
