// TFTP minimal decoder (RFC 1350)
pub fn decode(data: &[u8]) {
    if data.len() < 2 {
        println!("TFTP ({}B)", data.len());
        return;
    }
    let op = u16::from_be_bytes([data[0], data[1]]);
    let name = match op {
        1 => "RRQ",
        2 => "WRQ",
        3 => "DATA",
        4 => "ACK",
        5 => "ERROR",
        _ => "UNKNOWN",
    };
    println!("TFTP {}", name);
}
