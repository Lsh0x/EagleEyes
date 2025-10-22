// LDAP BER peek: detect BindRequest and version/name
fn ber_len(bytes: &[u8], i: &mut usize) -> Option<usize> {
    if *i >= bytes.len() {
        return None;
    }
    let b = bytes[*i];
    *i += 1;
    if b & 0x80 == 0 {
        return Some(b as usize);
    }
    let n = (b & 0x7F) as usize;
    if n == 0 || n > 4 || *i + n > bytes.len() {
        return None;
    }
    let mut v = 0usize;
    for _ in 0..n {
        v = (v << 8) | (bytes[*i] as usize);
        *i += 1;
    }
    Some(v)
}

pub fn decode(data: &[u8]) {
    let mut i = 0usize;
    if i >= data.len() || data[i] != 0x30 {
        println!("LDAP ({}B)", data.len());
        return;
    }
    i += 1;
    let _ = ber_len(data, &mut i).unwrap_or(0);
    // messageID
    if i >= data.len() || data[i] != 0x02 {
        println!("LDAP (no msgid)");
        return;
    }
    i += 1;
    let _ = ber_len(data, &mut i).unwrap_or(0);
    i += 1; // skip minimal id
            // protocolOp
    if i >= data.len() {
        println!("LDAP");
        return;
    }
    let tag = data[i];
    i += 1;
    let _op_len = ber_len(data, &mut i).unwrap_or(0);
    if tag == 0x60 {
        // BindRequest
        // version INTEGER
        if i < data.len() && data[i] == 0x02 {
            i += 1;
            let _ = ber_len(data, &mut i);
            let ver = data.get(i).copied().unwrap_or(0);
            i += 1;
            // name OCTET STRING
            if i < data.len() && data[i] == 0x04 {
                i += 1;
                if let Some(nl) = ber_len(data, &mut i) {
                    if i + nl <= data.len() {
                        let name = std::str::from_utf8(&data[i..i + nl]).unwrap_or("");
                        println!("LDAP BindRequest v{} name={}", ver, name);
                        return;
                    }
                }
            }
        }
    }
    println!("LDAP op=0x{:02x}", tag);
}
