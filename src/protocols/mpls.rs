#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
pub struct Shim {
    pub b0: u8,
    pub b1: u8,
    pub b2: u8,
    pub ttl: u8,
}

impl Shim {
    pub const SIZE: usize = 4;
}

fn parse_label(s: &Shim) -> (u32, u8, bool, u8) {
    let v = ((s.b0 as u32) << 24) | ((s.b1 as u32) << 16) | ((s.b2 as u32) << 8) | (s.ttl as u32);
    let label = (v >> 12) & 0xFFFFF;
    let tc = ((v >> 9) & 0x7) as u8;
    let s_bit = ((v >> 8) & 0x1) != 0;
    let ttl = (v & 0xFF) as u8;
    (label, tc, s_bit, ttl)
}

pub fn decode(mut data: &[u8]) {
    let mut depth = 0;
    while data.len() >= Shim::SIZE {
        let (h, rest) = data.split_at(Shim::SIZE);
        let s = Shim {
            b0: h[0],
            b1: h[1],
            b2: h[2],
            ttl: h[3],
        };
        let (label, tc, s_bit, ttl) = parse_label(&s);
        println!(
            "MPLS label={} tc={} s={} ttl={}",
            label, tc, s_bit as u8, ttl
        );
        depth += 1;
        data = rest;
        if s_bit {
            break;
        }
    }
    if data.is_empty() {
        return;
    }
    // Best-effort payload dispatch
    if data.len() >= 1 {
        let first = data[0] >> 4;
        match first {
            4 => super::ipv4::decode(data),
            6 => super::ipv6::decode(data),
            _ => println!("MPLS payload ({}B)", data.len()),
        }
    }
}
