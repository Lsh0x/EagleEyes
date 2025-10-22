// IEEE 802.2 LLC and SNAP
pub fn decode(data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let dsap = data[0];
    let ssap = data[1];
    let ctrl = data[2];
    if dsap == 0xAA && ssap == 0xAA && ctrl == 0x03 {
        // SNAP header: OUI(3) + Proto ID(2)
        if data.len() < 8 {
            return;
        }
        let oui = [data[3], data[4], data[5]];
        let pid = u16::from_be_bytes([data[6], data[7]]);
        println!(
            "LLC SNAP OUI={:02x}:{:02x}:{:02x} PID=0x{:04x}",
            oui[0], oui[1], oui[2], pid
        );
        let payload = &data[8..];
        // CDP: Cisco OUI 00:00:0C, PID 0x2000
        if oui == [0x00, 0x00, 0x0C] && pid == 0x2000 {
            return super::cdp::decode(payload);
        }
        println!("SNAP payload ({}B)", payload.len());
        return;
    }
    // STP (Spanning Tree) uses DSAP/SSAP 0x42, ctrl 0x03
    if dsap == 0x42 && ssap == 0x42 {
        return super::stp::decode(&data[3..]);
    }
    println!(
        "LLC DSAP=0x{:02x} SSAP=0x{:02x} CTRL=0x{:02x}",
        dsap, ssap, ctrl
    );
}
