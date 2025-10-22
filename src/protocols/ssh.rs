// Minimal SSH banner decoder
pub fn decode(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(line) = s.lines().next() {
            if line.starts_with("SSH-") {
                println!("SSH banner: {}", line.trim());
                return;
            }
        }
    }
    println!("SSH ({}B)", data.len());
}
