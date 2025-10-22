// Minimal STUN decoder (RFC 5389)
// Message: 2B type, 2B length, 4B magic cookie = 0x2112A442, 12B transaction ID

fn is_stun(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    cookie == 0x2112A442
}

pub fn decode(data: &[u8]) -> bool {
    if !is_stun(data) {
        return false;
    }
    let mtype = u16::from_be_bytes([data[0], data[1]]);
    let mlen = u16::from_be_bytes([data[2], data[3]]);
    println!("STUN type=0x{:04x} len={}", mtype, mlen);
    true
}
