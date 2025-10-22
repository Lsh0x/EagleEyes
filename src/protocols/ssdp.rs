// Minimal SSDP decoder (UPnP over UDP/1900)
// SSDP is HTTPU: print request/response line and ST/NT/USN headers if present.

pub fn decode(data: &[u8]) {
    let max = core::cmp::min(512, data.len());
    if let Ok(s) = std::str::from_utf8(&data[..max]) {
        let mut lines = s.lines();
        if let Some(first) = lines.next() {
            let mut st = "";
            let mut nt = "";
            let mut usn = "";
            for l in lines.by_ref().take(20) {
                // scan a few headers
                let l_low = l.to_ascii_lowercase();
                if l_low.starts_with("st:") {
                    st = l.trim();
                } else if l_low.starts_with("nt:") {
                    nt = l.trim();
                } else if l_low.starts_with("usn:") {
                    usn = l.trim();
                }
            }
            println!(
                "SSDP {} {} {}",
                first.trim(),
                st,
                if !nt.is_empty() { nt } else { usn }
            );
            return;
        }
    }
    println!("SSDP ({}B)", data.len());
}
