// RTSP minimal decoder (HTTP-like)
pub fn decode(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(line) = s.lines().next() {
            println!("RTSP: {}", line.trim());
            return;
        }
    }
    println!("RTSP ({}B)", data.len());
}
