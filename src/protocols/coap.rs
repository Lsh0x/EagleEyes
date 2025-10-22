// Minimal CoAP decoder (RFC 7252)
// Header: 1B ver(2)|type(2)|tkl(4), 1B code, 2B message ID, then token/options/payload

fn coap_type_name(t: u8) -> &'static str {
    match t {
        0 => "CON",
        1 => "NON",
        2 => "ACK",
        3 => "RST",
        _ => "?",
    }
}

pub fn decode(data: &[u8]) {
    if data.len() < 4 {
        println!("CoAP (truncated) {}B", data.len());
        return;
    }
    let b0 = data[0];
    let ver = (b0 >> 6) & 0x03;
    let typ = (b0 >> 4) & 0x03;
    let tkl = b0 & 0x0F;
    let code = data[1];
    let mid = u16::from_be_bytes([data[2], data[3]]);
    let cls = code >> 5; // class
    let detail = code & 0x1F;
    println!(
        "CoAP v{} {} tkl={} code={}.{} mid={}",
        ver,
        coap_type_name(typ),
        tkl,
        cls,
        detail,
        mid
    );
}
