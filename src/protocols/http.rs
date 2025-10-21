pub fn decode(data: &[u8]) {
    // very naive HTTP/1.x parser: print first line
    if data.is_empty() {
        return;
    }
    let max = core::cmp::min(256, data.len());
    if let Ok(s) = std::str::from_utf8(&data[..max]) {
        if let Some(line) = s.lines().next() {
            println!("HTTP: {}", line.trim());
        }
    }
}
