// Minimal FTP control channel decoder
pub fn decode(data: &[u8]) {
    // FTP control is ASCII lines
    let s = match std::str::from_utf8(data) {
        Ok(v) => v,
        Err(_) => {
            println!("FTP (binary) {}B", data.len());
            return;
        }
    };
    if let Some(line) = s.lines().next() {
        println!("FTP: {}", line.trim());
        if line.to_uppercase().starts_with("AUTH TLS") {
            println!("FTPS explicit requested");
        }
    } else {
        println!("FTP (empty)");
    }
}
