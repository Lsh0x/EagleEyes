// Minimal WebSocket detector/decoder
// Detect HTTP Upgrade handshake or simple data frames.

pub fn decode(data: &[u8]) -> bool {
    // Try HTTP handshake detection
    let max = core::cmp::min(1024, data.len());
    if let Ok(s) = std::str::from_utf8(&data[..max]) {
        if s.contains("Upgrade: websocket") {
            // Try to extract Sec-WebSocket-Key
            let key = s
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
                .map(|l| l.trim())
                .unwrap_or("");
            println!("WebSocket handshake {}", key);
            return true;
        }
    }
    // Try simple frame: FIN/opcode and mask bit
    if data.len() >= 2 {
        let b0 = data[0];
        let b1 = data[1];
        let fin = (b0 & 0x80) != 0;
        let opcode = b0 & 0x0F;
        let masked = (b1 & 0x80) != 0;
        println!(
            "WebSocket frame fin={} opcode=0x{:x} masked={}",
            fin, opcode, masked
        );
        return true;
    }
    false
}
