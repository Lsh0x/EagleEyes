// Cisco Discovery Protocol minimal decoder
pub fn decode(mut data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let ver = data[0];
    let ttl = data[1];
    let _cksum = u16::from_be_bytes([data[2], data[3]]);
    println!("CDP v{} ttl={}", ver, ttl);
    data = &data[4..];
    while data.len() >= 4 {
        let t = u16::from_be_bytes([data[0], data[1]]);
        let l = u16::from_be_bytes([data[2], data[3]]) as usize;
        if l < 4 || data.len() < l {
            break;
        }
        let v = &data[4..l];
        match t {
            0x0001 => {
                // Device ID
                if let Ok(s) = std::str::from_utf8(v) {
                    println!("CDP DeviceID {}", s);
                } else {
                    println!("CDP DeviceID ({}B)", v.len());
                }
            }
            0x0003 => {
                // Port ID
                if let Ok(s) = std::str::from_utf8(v) {
                    println!("CDP PortID {}", s);
                } else {
                    println!("CDP PortID ({}B)", v.len());
                }
            }
            0x0005 => println!("CDP Software Version ({}B)", v.len()),
            0x0006 => println!("CDP Platform ({}B)", v.len()),
            0x0002 => println!("CDP Addresses ({}B)", v.len()),
            _ => println!("CDP TLV type=0x{:04x} len={}", t, l),
        }
        data = &data[l..];
    }
}
