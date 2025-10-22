pub fn decode(eth_type: u16, data: &[u8]) {
    // PPPoE header: Ver/Type (1), Code (1), SessionID (2), Length (2)
    if data.len() < 6 {
        return;
    }
    let ver_type = data[0];
    let code = data[1];
    let sid = u16::from_be_bytes([data[2], data[3]]);
    let len = u16::from_be_bytes([data[4], data[5]]) as usize;
    println!(
        "PPPoE v{} t{} code=0x{:02x} sid={} len={}",
        ver_type >> 4,
        ver_type & 0x0f,
        code,
        sid,
        len
    );
    if data.len() < 6 + len {
        return;
    }
    let payload = &data[6..6 + len];
    if eth_type == super::ethernet::PROTO::PPPOE_DISC {
        // Discovery tags (Type 2, Length 2, Value)
        let mut p = payload;
        while p.len() >= 4 {
            let t = u16::from_be_bytes([p[0], p[1]]);
            let l = u16::from_be_bytes([p[2], p[3]]) as usize;
            p = &p[4..];
            if p.len() < l {
                break;
            }
            println!("PPPoE TAG type=0x{:04x} len={}", t, l);
            p = &p[l..];
        }
        return;
    }
    // Session: first two bytes are PPP Protocol
    if payload.len() < 2 {
        return;
    }
    let ppp_proto = u16::from_be_bytes([payload[0], payload[1]]);
    match ppp_proto {
        0x0021 => super::ipv4::decode(&payload[2..]), // IPv4
        0x0057 => super::ipv6::decode(&payload[2..]), // IPv6
        0xc021 => println!("PPP LCP ({}B)", payload.len() - 2),
        0xc023 => println!("PPP PAP ({}B)", payload.len() - 2),
        0xc223 => println!("PPP CHAP ({}B)", payload.len() - 2),
        _ => println!("PPP proto=0x{:04x} ({}B)", ppp_proto, payload.len() - 2),
    }
}
