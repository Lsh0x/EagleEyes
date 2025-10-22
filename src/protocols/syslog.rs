// Syslog minimal decoder
pub fn decode(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(line) = s.lines().next() {
            println!("Syslog: {}", line.trim());
            return;
        }
    }
    println!("Syslog ({}B)", data.len());
}
