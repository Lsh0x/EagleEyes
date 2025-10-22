// Minimal LIN decoder
// Print frame id (6-bit), parity bits, and data length guess
pub fn decode(data: &[u8]) {
    if data.is_empty() {
        println!("LIN (empty)");
        return;
    }
    let pid = data[0];
    let id = pid & 0x3F;
    let p = (pid & 0xC0) >> 6;
    let dlen = data.len().saturating_sub(1).min(8);
    println!(
        "LIN id=0x{:02x} parity={} len={} data={:02x?}",
        id,
        p,
        dlen,
        &data[1..1 + dlen]
    );
}
