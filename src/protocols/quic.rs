// Very coarse QUIC detection (long header, type, version)
pub fn decode(data: &[u8]) {
    if data.len() < 6 {
        return;
    }
    let first = data[0];
    let long_hdr = (first & 0x80) != 0;
    if !long_hdr {
        println!("QUIC short header (likely 1-RTT)");
        return;
    }
    let pkt_type = (first & 0x30) >> 4; // 0=Initial
    let vbytes = [data[1], data[2], data[3], data[4]];
    let version = u32::from_be_bytes(vbytes);
    let mut flavor = "IETF";
    if vbytes[0] == b'Q' {
        flavor = "GQUIC";
    }
    let mut note = String::new();
    if flavor == "IETF" && (version == 1 || (version & 0xFF00_0000) == 0xFF00_0000) {
        note = " (HTTP/3 likely)".into();
    }
    println!(
        "QUIC {} long_hdr type={} version=0x{:08x}{}",
        flavor, pkt_type, version, note
    );
}
