// SIP minimal decoder
pub fn decode(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(line) = s.lines().next() {
            if line.starts_with("SIP/")
                || line.to_uppercase().starts_with("INVITE ")
                || line.to_uppercase().starts_with("REGISTER ")
            {
                println!("SIP: {}", line.trim());
                return;
            }
        }
    }
    println!("SIP ({}B)", data.len());
}
