// Minimal Frame Relay (RFC 2427) decoder
pub fn decode(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    // Parse first two bytes of address field (DLCI, FECN/BECN/DE)
    let b0 = data[0];
    let b1 = data[1];
    let dlci = ((b0 as u16 & 0xFC) << 2) | ((b1 as u16 & 0xF0) >> 4);
    let fecn = (b1 & 0x08) != 0;
    let becn = (b1 & 0x04) != 0;
    let de = (b1 & 0x02) != 0;
    println!(
        "FR DLCI={} FECN={} BECN={} DE={}",
        dlci, fecn as u8, becn as u8, de as u8
    );
    // Heuristic payload: many FR carry NLPID or SNAP
    if data.len() > 2 {
        println!("FR payload ({}B)", data.len() - 2);
    }
}
