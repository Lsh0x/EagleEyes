// SSH: banner or binary packet length
pub fn decode(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(line) = s.lines().next() {
            if line.starts_with("SSH-") {
                println!("SSH banner: {}", line.trim());
                return;
            }
        }
    }
    if data.len() >= 5 {
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if len + 4 <= data.len() && len < 35000 {
            println!("SSH binary packet len={}", len);
            return;
        }
    }
    println!("SSH ({}B)", data.len());
}
