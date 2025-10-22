// POP3 minimal decoder
pub fn decode(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(line) = s.lines().next() {
            println!("POP3: {}", line.trim());
            return;
        }
    }
    println!("POP3 ({}B)", data.len());
}
