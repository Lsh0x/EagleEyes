// IMAP line parser: print tag and command verb
pub fn decode(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(line) = s.lines().next() {
            let mut it = line.split_whitespace();
            let tag = it.next().unwrap_or("");
            let cmd = it.next().unwrap_or("").to_uppercase();
            if !tag.is_empty() && !cmd.is_empty() {
                println!("IMAP tag={} cmd={}", tag, cmd);
                return;
            }
            println!("IMAP: {}", line.trim());
            return;
        }
    }
    println!("IMAP ({}B)", data.len());
}
