// Minimal HDLC decoder (Cisco/PPP HDLC-like)
pub fn decode(data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    // Most captures store HDLC without flags/bit-stuffing at L2+; here show first bytes
    let addr = data[0];
    let control = data[1];
    println!(
        "HDLC addr=0x{:02x} ctrl=0x{:02x} ({}B)",
        addr,
        control,
        data.len()
    );
    // If PPP over HDLC, next is PPP protocol
    if data.len() >= 4 {
        let proto = u16::from_be_bytes([data[2], data[3]]);
        println!("HDLC PPP proto=0x{:04x}", proto);
    }
}
