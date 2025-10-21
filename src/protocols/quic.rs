// Very coarse QUIC Initial detection (long header, type=Initial)
pub fn decode(data: &[u8]) {
    if data.len() < 6 {
        return;
    }
    let first = data[0];
    let long_hdr = (first & 0x80) != 0;
    if !long_hdr {
        println!("UDP/443 non-QUIC");
        return;
    }
    let pkt_type = (first & 0x30) >> 4; // 0=Initial
    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    println!("QUIC long_hdr type={} version=0x{:08x}", pkt_type, version);
}
