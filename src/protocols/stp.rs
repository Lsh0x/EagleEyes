// STP BPDU minimal decoder
pub fn decode(data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let proto_id = u16::from_be_bytes([data[0], data[1]]);
    let ver = data[2];
    let typ = data[3];
    println!(
        "STP proto_id=0x{:04x} ver={} type=0x{:02x}",
        proto_id, ver, typ
    );
    if typ == 0x00 {
        // Configuration BPDU
        if data.len() < 35 {
            return;
        }
        let flags = data[4];
        let root_prio = u16::from_be_bytes([data[5], data[6]]);
        let root_mac = &data[7..13];
        let path_cost = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
        let bridge_prio = u16::from_be_bytes([data[17], data[18]]);
        let bridge_mac = &data[19..25];
        let port_id = u16::from_be_bytes([data[25], data[26]]);
        println!("STP cfg flags=0x{:02x} root={}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} cost={} bridge={}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} port=0x{:04x}",
            flags,
            root_prio,
            root_mac[0], root_mac[1], root_mac[2], root_mac[3], root_mac[4],
            path_cost,
            bridge_prio,
            bridge_mac[0], bridge_mac[1], bridge_mac[2], bridge_mac[3], bridge_mac[4],
            port_id);
    }
}
