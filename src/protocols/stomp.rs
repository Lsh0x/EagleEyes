// Minimal STOMP decoder
// STOMP frames are text-based, first line is the command (e.g., CONNECT, SEND)

pub fn decode(data: &[u8]) {
    let max = core::cmp::min(256, data.len());
    if let Ok(s) = std::str::from_utf8(&data[..max]) {
        if let Some(line) = s.lines().next() {
            let cmd = line.trim();
            println!("STOMP {}", cmd);
            return;
        }
    }
    println!("STOMP ({}B)", data.len());
}
