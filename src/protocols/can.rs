// Minimal SocketCAN decoder
// SocketCAN frame: 4B can_id, 1B dlc, 3B pad, 8B data
pub fn decode(data: &[u8]) {
    if data.len() >= 16 {
        let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let dlc = data[4] & 0x0F;
        println!(
            "CAN id=0x{:08x} dlc={} data={:02x?}",
            id,
            dlc,
            &data[8..(8 + (dlc as usize)).min(16)]
        );
    } else {
        println!("CAN ({}B)", data.len());
    }
}
