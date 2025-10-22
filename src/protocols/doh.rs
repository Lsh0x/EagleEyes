// Minimal DNS-over-HTTPS (DoH) detector for HTTP/1.x plaintext
// Looks for request path or content-type indicating DoH.
// Returns true if it looked like DoH and printed something.

pub fn decode(data: &[u8]) -> bool {
    let max = core::cmp::min(1024, data.len());
    let s = match std::str::from_utf8(&data[..max]) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut lines = s.lines();
    let first = match lines.next() {
        Some(v) => v,
        None => return false,
    };
    // Check request path
    let doh_path = first.contains("/dns-query");
    let mut is_doh = doh_path;
    let mut ct = "";
    for l in lines.by_ref().take(40) {
        let ll = l.to_ascii_lowercase();
        if ll.starts_with("content-type:") {
            ct = l.trim();
            if ll.contains("application/dns-message") || ll.contains("application/dns-json") {
                is_doh = true;
            }
        }
    }
    if is_doh {
        println!("DoH {} {}", first.trim(), ct);
        return true;
    }
    false
}
