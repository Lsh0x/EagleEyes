// BGP-4 minimal decoder over TCP/179
pub fn decode(data: &[u8]) {
    if data.len() < 19 {
        // 16 marker + 2 len + 1 type
        println!("BGP (truncated) {}B", data.len());
        return;
    }
    let marker_ffff = data[..16].iter().all(|&b| b == 0xff);
    let len = u16::from_be_bytes([data[16], data[17]]) as usize;
    let typ = data[18];
    let tname = match typ {
        1 => "OPEN",
        2 => "UPDATE",
        3 => "NOTIF",
        4 => "KEEPALIVE",
        5 => "ROUTE-REFRESH",
        _ => "UNKNOWN",
    };
    println!(
        "BGP {} len={} marker={}B",
        tname,
        len,
        if marker_ffff { 16 } else { 0 }
    );
}
