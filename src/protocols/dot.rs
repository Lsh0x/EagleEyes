// Minimal DNS-over-TLS (DoT) helper
// If plaintext (non-TLS) is seen (non-standard), try to parse 2-byte length-prefixed DNS message.

pub fn decode(data: &[u8]) {
    // Try to parse length-prefixed DNS; if too short, just label DoT
    if data.len() >= 2 {
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() >= 2 + len {
            println!("DoT DNS len={}", len);
            super::dns::decode(&data[2..2 + len]);
            return;
        }
    }
    println!("DoT (TLS likely) {}B", data.len());
}
