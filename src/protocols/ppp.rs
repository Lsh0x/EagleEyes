// Minimal PPP decoder (RFC 1661)
// Handles optional Address/Control (0xff,0x03) and 1- or 2-byte Protocol field.
// Dispatches IPv4/IPv6 payloads; prints LCP/IPCP/IPv6CP/PAP/CHAP otherwise.

fn proto_name(p: u16) -> &'static str {
    match p {
        0x0021 => "IPv4",
        0x0057 => "IPv6",
        0x8021 => "IPCP",
        0x8057 => "IPv6CP",
        0xC021 => "LCP",
        0xC023 => "PAP",
        0xC223 => "CHAP",
        _ => "PPP",
    }
}

pub fn decode(data: &[u8]) {
    if data.len() < 1 {
        println!("PPP (empty)");
        return;
    }
    let mut i = 0usize;
    // Optional Address/Control
    if data.len() >= 2 && data[0] == 0xff && data[1] == 0x03 {
        i = 2;
    }
    if i >= data.len() {
        println!("PPP (no protocol)");
        return;
    }
    // Protocol field is 1 or 2 bytes: if first byte is odd, it's 1 byte (compressed); else 2 bytes
    let (proto, hdr_len) = if data[i] & 1 != 0 {
        (data[i] as u16, 1usize)
    } else if i + 1 < data.len() {
        (((data[i] as u16) << 8) | data[i + 1] as u16, 2usize)
    } else {
        (data[i] as u16, 1usize)
    };
    let payload = &data[i + hdr_len..];
    match proto {
        0x0021 => {
            // IPv4
            println!("PPP {}", proto_name(proto));
            crate::protocols::ipv4::decode(payload);
        }
        0x0057 => {
            // IPv6
            println!("PPP {}", proto_name(proto));
            crate::protocols::ipv6::decode(payload);
        }
        _ => {
            println!("PPP {} ({}B)", proto_name(proto), payload.len());
        }
    }
}
