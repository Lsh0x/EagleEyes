// Minimal Loopback/Null decoder
// BSD NULL/LOOP: 4-byte AF family (host-endian), then payload
use crate::protocols::{ipv4, ipv6};

pub fn decode(data: &[u8]) {
    if data.len() < 4 {
        println!("LOOP/NULL ({}B)", data.len());
        return;
    }
    let fam = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    let payload = &data[4..];
    match fam {
        2 => {
            // AF_INET
            ipv4::decode(payload);
        }
        24 | 28 | 30 => {
            // AF_INET6 common values
            ipv6::decode(payload);
        }
        _ => {
            println!("LOOP fam={} ({}B)", fam, payload.len());
        }
    }
}
