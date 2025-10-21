// returns true if looked like TLS ClientHello and we printed it
pub fn decode(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    // TLS record header
    let content_type = data[0];
    let _ver = u16::from_be_bytes([data[1], data[2]]);
    let len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if content_type != 0x16 || data.len() < 5 + len {
        return false;
    }
    if data.len() < 10 {
        return false;
    }
    let hs_type = data[5];
    if hs_type != 0x01 {
        return false;
    }
    // very rough SNI parse
    // skip record(5) + hs header(4) + client_version(2) + random(32)
    let mut i = 5 + 4 + 2 + 32;
    if data.len() <= i {
        return true;
    }
    let sid_len = data[i] as usize;
    i += 1 + sid_len;
    if data.len() <= i + 2 {
        return true;
    }
    let cs_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2 + cs_len;
    if data.len() <= i + 1 {
        return true;
    }
    let comp_len = data[i] as usize;
    i += 1 + comp_len;
    if data.len() <= i + 2 {
        return true;
    }
    let ext_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;
    let end = core::cmp::min(data.len(), i + ext_len);
    let mut sni: Option<String> = None;
    let mut j = i;
    while j + 4 <= end {
        let et = u16::from_be_bytes([data[j], data[j + 1]]);
        j += 2;
        let el = u16::from_be_bytes([data[j], data[j + 1]]) as usize;
        j += 2;
        if j + el > end {
            break;
        }
        if et == 0x0000 && el >= 5 {
            // server_name ext; skip list len(2) + name_type(1) + name_len(2)
            let nl = u16::from_be_bytes([data[j + 3], data[j + 4]]) as usize;
            if j + 5 + nl <= end {
                if let Ok(host) = std::str::from_utf8(&data[j + 5..j + 5 + nl]) {
                    sni = Some(host.to_string());
                }
            }
        }
        j += el;
    }
    if let Some(h) = sni {
        println!("TLS ClientHello SNI={}", h);
    } else {
        println!("TLS ClientHello");
    }
    true
}
