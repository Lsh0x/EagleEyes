// SIP parse: print request/response line and core headers
pub fn decode(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        let mut lines = s.lines();
        if let Some(first) = lines.next() {
            if first.starts_with("SIP/")
                || first
                    .split_whitespace()
                    .next()
                    .map(|m| {
                        m.eq_ignore_ascii_case("INVITE")
                            || m.eq_ignore_ascii_case("REGISTER")
                            || m.eq_ignore_ascii_case("ACK")
                            || m.eq_ignore_ascii_case("BYE")
                    })
                    .unwrap_or(false)
            {
                let mut from = "";
                let mut to = "";
                let mut call_id = "";
                let mut cseq = "";
                for l in lines.by_ref().take(40) {
                    let ll = l.to_ascii_lowercase();
                    if ll.starts_with("from:") {
                        from = l.trim();
                    } else if ll.starts_with("to:") {
                        to = l.trim();
                    } else if ll.starts_with("call-id:") {
                        call_id = l.trim();
                    } else if ll.starts_with("cseq:") {
                        cseq = l.trim();
                    }
                }
                println!("SIP {} | {} | {} | {}", first.trim(), from, to, call_id);
                if !cseq.is_empty() {
                    println!("SIP {}", cseq);
                }
                return;
            }
        }
    }
    println!("SIP ({}B)", data.len());
}
